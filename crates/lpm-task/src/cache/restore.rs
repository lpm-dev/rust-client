use super::*;

const RESTORE_JOURNAL_NAME: &str = "transaction.bin";
pub(super) const RESTORE_JOURNAL_MAGIC: &[u8] = b"LPMRESTORE\x02";
pub(super) const RESTORE_OWNER_NAME: &str = "owner";
const RESTORE_OWNER_MAGIC: &[u8] = b"LPMRESTOREOWNER\x01";
const RESTORE_COMMITTED_NAME: &str = "committed";
const RESTORE_COMMITTED_MAGIC: &[u8] = b"LPMRESTORECOMMITTED\x01";
const RESTORE_REGISTRY_MAGIC_V1: &[u8] = b"LPMRESTORERECORD\x01";
const RESTORE_REGISTRY_MAGIC: &[u8] = b"LPMRESTORERECORD\x02";
const RESTORE_REGISTRY_DIR: &str = ".task-restores";
const RESTORE_TOKEN_BYTES: usize = 32;
const MAX_RESTORE_REGISTRY_BYTES: u64 = 16 * 1024;
const MAX_RESTORE_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;

/// Restore a cache archive only after all entries pass validation.
#[cfg(test)]
pub(super) fn restore_archive(archive_path: &Path, project_dir: &Path) -> Result<(), LpmError> {
    let root_dir = tempfile::tempdir()?;
    let root = LpmRoot::from_dir(root_dir.path());
    ensure_real_file(archive_path, "task cache archive")?;
    let archive = std::fs::File::open(archive_path)?;
    let staged = stage_cache_archive(&root, archive, project_dir, "task cache archive")?;
    staged.apply(&[])
}

pub(super) fn restore_archive_with_expected_count_if(
    root: &LpmRoot,
    archive: std::fs::File,
    project: &OpenProject,
    expected_count: usize,
    output_globs: &[String],
    validate: impl FnOnce() -> Result<bool, LpmError>,
) -> Result<bool, LpmError> {
    let staged = stage_cache_archive_with_project(root, archive, project, "task cache archive")?;
    if staged.file_count() != expected_count {
        return Err(LpmError::Task(format!(
            "cache entry output count mismatch (expected {expected_count}, found {})",
            staged.file_count()
        )));
    }
    staged.apply_if(output_globs, validate)
}

#[cfg(test)]
fn stage_cache_archive(
    root: &LpmRoot,
    archive_file: std::fs::File,
    project_dir: &Path,
    label: &str,
) -> Result<StagedOutputs, LpmError> {
    let project = open_project(project_dir)?;
    stage_cache_archive_with_project(root, archive_file, &project, label)
}

fn stage_cache_archive_with_project(
    root: &LpmRoot,
    archive_file: std::fs::File,
    project: &OpenProject,
    label: &str,
) -> Result<StagedOutputs, LpmError> {
    let dec = flate2::read::GzDecoder::new(archive_file);
    let mut total_bytes: u64 = 0;
    let mut staged = StagedOutputs::new_with_project(root, project)?;
    let archive_limits = lpm_extractor::TarArchiveLimits {
        max_entry_bytes: MAX_CACHE_ENTRY_BYTES,
        ..lpm_extractor::TarArchiveLimits::new(MAX_CACHE_ARCHIVE_ENTRIES)
    };

    lpm_extractor::visit_tar_archive(dec, archive_limits, |mut entry| {
        let path = entry.path().to_path_buf();
        validate_archive_path(&path, label)?;
        validate_archive_entry_type(entry.header().entry_type(), &path, label)?;

        let entry_size = entry.header().size().unwrap_or(0);
        check_archive_size_limits(entry_size, &mut total_bytes, &path, label)?;
        let header = entry.header().clone();
        staged.append(&mut entry, &header, &path)?;
        Ok(std::ops::ControlFlow::<()>::Continue(()))
    })?;

    Ok(staged)
}

pub(super) fn scan_cache_archive(
    archive_file: std::fs::File,
    label: &str,
) -> Result<usize, LpmError> {
    let dec = flate2::read::GzDecoder::new(archive_file);
    let mut total_bytes = 0;
    let mut paths = HashSet::new();
    let mut file_count = 0;
    let archive_limits = lpm_extractor::TarArchiveLimits {
        max_entry_bytes: MAX_CACHE_ENTRY_BYTES,
        ..lpm_extractor::TarArchiveLimits::new(MAX_CACHE_ARCHIVE_ENTRIES)
    };

    lpm_extractor::visit_tar_archive(dec, archive_limits, |mut entry| {
        let path = entry.path().to_path_buf();
        validate_archive_path(&path, label)?;
        validate_archive_entry_type(entry.header().entry_type(), &path, label)?;
        let entry_size = entry.header().size().unwrap_or(0);
        check_archive_size_limits(entry_size, &mut total_bytes, &path, label)?;
        let normalized = normalize_archive_path(&path, label)?;
        if !paths.insert(normalized) {
            return Err(LpmError::Task(format!(
                "{label} contains duplicate entry: {}",
                path.display()
            )));
        }
        if entry.header().entry_type().is_file() {
            file_count += 1;
            std::io::copy(&mut entry, &mut std::io::sink()).map_err(|error| {
                LpmError::Task(format!("failed to read {}: {error}", path.display()))
            })?;
        }
        Ok(std::ops::ControlFlow::<()>::Continue(()))
    })?;

    Ok(file_count)
}

pub(super) struct StagedOutputs {
    temp_path: PathBuf,
    staging: Option<Dir>,
    project: Dir,
    output: Dir,
    canonical_project: PathBuf,
    registry_record: RestoreRegistryRecord,
    token: [u8; RESTORE_TOKEN_BYTES],
    cleanup_registry_on_drop: bool,
    seen_paths: HashSet<PathBuf>,
    files: Vec<PathBuf>,
}

impl StagedOutputs {
    #[cfg(test)]
    pub(super) fn new(root: &LpmRoot, project_dir: &Path) -> Result<Self, LpmError> {
        let project = open_project(project_dir)?;
        Self::new_with_project(root, &project)
    }

    pub(super) fn new_with_project(
        root: &LpmRoot,
        open_project: &OpenProject,
    ) -> Result<Self, LpmError> {
        let canonical_project = open_project.path.clone();
        let project = open_project.dir.try_clone()?;
        let registry_record = restore_registry_record(root, &canonical_project)?;
        recover_interrupted_restore(&canonical_project, &registry_record)?;
        let temp = tempfile::Builder::new()
            .prefix(RESTORE_TEMP_PREFIX)
            .tempdir_in(&canonical_project)?;
        let staging_name = temp.path().strip_prefix(&canonical_project).map_err(|_| {
            LpmError::Task("task cache restore staging directory escaped the project".into())
        })?;
        let staging = project.open_dir_nofollow(staging_name)?;
        restrict_open_directory(&staging, "task cache restore staging directory")?;
        sync_cap_directory(&project)?;
        let mut token = [0u8; RESTORE_TOKEN_BYTES];
        getrandom::fill(&mut token).map_err(|error| {
            LpmError::Task(format!(
                "failed to create task cache restore token: {error}"
            ))
        })?;
        write_restore_owner_open(&staging, &token)?;
        staging.create_dir("outputs")?;
        staging.create_dir("backups")?;
        sync_cap_directory(&staging)?;
        let output = staging.open_dir_nofollow("outputs")?;
        write_restore_registration(&registry_record, temp.path(), &token, false)?;
        let temp_path = temp.keep();

        Ok(Self {
            temp_path,
            staging: Some(staging),
            project,
            output,
            canonical_project,
            registry_record,
            token,
            cleanup_registry_on_drop: true,
            seen_paths: HashSet::new(),
            files: Vec::new(),
        })
    }

    pub(super) fn append(
        &mut self,
        entry: &mut impl Read,
        header: &tar::Header,
        archive_path: &Path,
    ) -> Result<(), LpmError> {
        let relative = normalize_archive_path(archive_path, "task cache archive")?;
        if !self.seen_paths.insert(relative.clone()) {
            return Err(LpmError::Task(format!(
                "task cache archive contains duplicate entry: {}",
                archive_path.display()
            )));
        }

        if header.entry_type().is_dir() {
            create_directory_path_nofollow(&self.output, &relative, "staged output")?;
            return Ok(());
        }

        let (parent, name) = open_or_create_parent_nofollow(
            &self.output,
            &relative,
            "staged output",
            DirectoryCreationDurability::Deferred,
        )?;
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
        let mut staged_file = parent
            .open_with(&name, &options)
            .map(cap_std::fs::File::into_std)
            .map_err(|error| {
                LpmError::Task(format!(
                    "failed to stage task cache output {}: {error}",
                    archive_path.display()
                ))
            })?;
        let archived_mtime = header.mtime().map_err(|error| {
            LpmError::Task(format!(
                "failed to read task cache output timestamp {}: {error}",
                archive_path.display()
            ))
        })?;
        std::io::copy(entry, &mut staged_file).map_err(|error| {
            LpmError::Task(format!(
                "failed to stage task cache output {}: {error}",
                archive_path.display()
            ))
        })?;
        staged_file.set_times(
            std::fs::FileTimes::new().set_modified(
                std::time::SystemTime::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(archived_mtime))
                    .ok_or_else(|| {
                        LpmError::Task(format!(
                            "task cache output timestamp is out of range: {}",
                            archive_path.display()
                        ))
                    })?,
            ),
        )?;
        set_staged_file_permissions(&staged_file, header.mode().unwrap_or(0o644))?;
        #[cfg(test)]
        {
            let failure = STAGED_FILE_FINALIZE_FAILURE
                .lock()
                .expect("staged file finalize failure lock")
                .clone();
            if failure.is_some_and(|failure| {
                failure.project == self.canonical_project && failure.relative == relative
            }) {
                return Err(LpmError::Task(format!(
                    "failed to finalize staged task cache output {}: injected failure",
                    relative.display()
                )));
            }
        }
        staged_file.flush().map_err(|error| {
            LpmError::Task(format!(
                "failed to finalize staged task cache output {}: {error}",
                relative.display()
            ))
        })?;
        self.files.push(relative);
        Ok(())
    }

    pub(super) fn file_count(&self) -> usize {
        self.files.len()
    }

    #[cfg(test)]
    pub(super) fn apply(self, output_globs: &[String]) -> Result<(), LpmError> {
        if self.apply_if(output_globs, || Ok(true))? {
            Ok(())
        } else {
            Err(LpmError::Task(
                "task cache restore validation unexpectedly rejected an unconditional restore"
                    .into(),
            ))
        }
    }

    pub(super) fn apply_if(
        self,
        output_globs: &[String],
        validate: impl FnOnce() -> Result<bool, LpmError>,
    ) -> Result<bool, LpmError> {
        let mut this = self;
        verify_open_directory_path(
            &this.project,
            &this.canonical_project,
            "task cache project directory",
        )?;
        let install_count = this.files.len();
        let mut stale_outputs = collect_output_files(&this.canonical_project, output_globs)?;
        verify_open_directory_path(
            &this.project,
            &this.canonical_project,
            "task cache project directory",
        )?;
        stale_outputs.retain(|relative| !this.seen_paths.contains(relative));
        if install_count.saturating_add(stale_outputs.len()) > MAX_CACHE_ARCHIVE_ENTRIES {
            return Err(LpmError::Task(format!(
                "task cache restore exceeds entry-count cap ({MAX_CACHE_ARCHIVE_ENTRIES} entries)"
            )));
        }
        this.files.extend(stale_outputs);

        let existing_outputs = write_restore_journal_for_plan_open(
            this.staging
                .as_ref()
                .expect("restore staging directory exists"),
            &this.project,
            &this.canonical_project,
            &this.files,
            install_count,
        )?;

        let mut transaction = RestoreTransaction::new_with_open_staging(
            this.canonical_project.clone(),
            this.project.try_clone()?,
            this.staging
                .as_ref()
                .expect("restore staging directory exists"),
            this.files.len(),
        )?;
        let installed_trees =
            match transaction.install_missing_top_level_trees(&this.files[..install_count]) {
                Ok(installed) => installed,
                Err(error) => {
                    let (error, rollback_failed) = transaction.rollback_error(error);
                    drop(transaction);
                    if rollback_failed {
                        return Err(this.preserve_recovery_data(error));
                    }
                    return Err(error);
                }
            };
        for (index, (relative, had_existing)) in this.files.iter().zip(existing_outputs).enumerate()
        {
            let installed_as_tree = index < install_count
                && relative.components().next().is_some_and(|component| {
                    let Component::Normal(root) = component else {
                        return false;
                    };
                    installed_trees.contains(root)
                });
            if installed_as_tree {
                continue;
            }
            let operation = if index < install_count {
                transaction.install(relative, had_existing)
            } else {
                transaction.remove(relative, had_existing)
            };
            if let Err(error) = operation {
                let (error, rollback_failed) = transaction.rollback_error(error);
                drop(transaction);
                if rollback_failed {
                    return Err(this.preserve_recovery_data(error));
                }
                return Err(error);
            }
        }
        match validate() {
            Ok(true) => {}
            Ok(false) => {
                let error = LpmError::Task(
                    "task cache context changed while cached outputs were restored".into(),
                );
                let (error, rollback_failed) = transaction.rollback_error(error);
                drop(transaction);
                if rollback_failed {
                    return Err(this.preserve_recovery_data(error));
                }
                return Ok(false);
            }
            Err(error) => {
                let (error, rollback_failed) = transaction.rollback_error(error);
                drop(transaction);
                if rollback_failed {
                    return Err(this.preserve_recovery_data(error));
                }
                return Err(error);
            }
        }
        if let Err(error) = transaction.prepare_commit() {
            let (error, rollback_failed) = transaction.rollback_error(error);
            drop(transaction);
            if rollback_failed {
                return Err(this.preserve_recovery_data(error));
            }
            return Err(error);
        }
        if let Err(error) =
            write_restore_registration(&this.registry_record, &this.temp_path, &this.token, true)
        {
            let (error, rollback_failed) = transaction.rollback_error(error);
            drop(transaction);
            if rollback_failed {
                return Err(this.preserve_recovery_data(error));
            }
            return Err(error);
        }
        transaction.mark_committed();
        drop(transaction);
        this.cleanup_registry_on_drop = false;
        cleanup_open_staging(
            &this.project,
            Path::new(this.temp_path.file_name().ok_or_else(|| {
                LpmError::Task("restore staging directory has no file name".into())
            })?),
            this.staging
                .take()
                .expect("restore staging directory exists"),
        )?;
        remove_restore_registration(&this.registry_record)?;
        Ok(true)
    }

    #[cfg(test)]
    pub(super) fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    pub(super) fn preserve_recovery_data(&mut self, error: LpmError) -> LpmError {
        self.cleanup_registry_on_drop = false;
        self.staging.take();
        LpmError::Task(format!(
            "{error}; recovery data was preserved at {}",
            self.temp_path.display()
        ))
    }
}

impl Drop for StagedOutputs {
    fn drop(&mut self) {
        if self.cleanup_registry_on_drop {
            let cleanup_succeeded = if let Some(staging) = self.staging.take()
                && let Some(name) = self.temp_path.file_name()
            {
                cleanup_open_staging(&self.project, Path::new(name), staging).is_ok()
            } else {
                true
            };
            if cleanup_succeeded {
                let _ = remove_restore_registration(&self.registry_record);
            }
        }
    }
}

#[cfg(test)]
pub(super) fn write_restore_journal(
    restore_dir: &Path,
    project_dir: &Path,
    files: &[PathBuf],
) -> Result<Vec<bool>, LpmError> {
    write_restore_journal_for_plan(restore_dir, project_dir, files, files.len())
}

#[cfg(test)]
fn write_restore_journal_for_plan(
    restore_dir: &Path,
    project_dir: &Path,
    files: &[PathBuf],
    install_count: usize,
) -> Result<Vec<bool>, LpmError> {
    let restore = Dir::open_ambient_dir(restore_dir, cap_std::ambient_authority())?;
    let project = Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())?;
    write_restore_journal_for_plan_open(&restore, &project, project_dir, files, install_count)
}

fn write_restore_journal_for_plan_open(
    restore: &Dir,
    project: &Dir,
    project_dir: &Path,
    files: &[PathBuf],
    install_count: usize,
) -> Result<Vec<bool>, LpmError> {
    use std::io::BufWriter;

    if files.len() > MAX_CACHE_ARCHIVE_ENTRIES || install_count > files.len() {
        return Err(LpmError::Task(format!(
            "task cache restore journal exceeds output-count cap ({MAX_CACHE_ARCHIVE_ENTRIES} entries)"
        )));
    }
    let (existing_outputs, missing_directories) =
        analyze_restore_plan(project, project_dir, files, install_count)?;
    write_open_file_atomic_with(
        restore,
        std::ffi::OsStr::new(RESTORE_JOURNAL_NAME),
        |file| {
            let mut writer = BufWriter::with_capacity(64 * 1024, file);
            writer.write_all(RESTORE_JOURNAL_MAGIC)?;
            let file_count = u32::try_from(files.len())
                .map_err(|_| LpmError::Task("too many task cache outputs for recovery".into()))?;
            writer.write_all(&file_count.to_le_bytes())?;
            let mut journal_bytes = RESTORE_JOURNAL_MAGIC.len() as u64 + 4;

            for (relative, had_existing) in files.iter().zip(&existing_outputs) {
                let path_bytes = restore_journal_path_bytes(relative);
                let path_len = u32::try_from(path_bytes.len()).map_err(|_| {
                    LpmError::Task(format!(
                        "task cache restore path is too long for recovery: {}",
                        relative.display()
                    ))
                })?;
                journal_bytes = journal_bytes.saturating_add(5 + u64::from(path_len));
                if journal_bytes > MAX_RESTORE_JOURNAL_BYTES {
                    return Err(LpmError::Task(format!(
                        "task cache restore journal exceeds {MAX_RESTORE_JOURNAL_BYTES} bytes"
                    )));
                }
                writer.write_all(&[u8::from(*had_existing)])?;
                writer.write_all(&path_len.to_le_bytes())?;
                writer.write_all(&path_bytes)?;
            }

            let directory_count = u32::try_from(missing_directories.len()).map_err(|_| {
                LpmError::Task("too many task cache directories for recovery".into())
            })?;
            writer.write_all(&directory_count.to_le_bytes())?;
            journal_bytes = journal_bytes.saturating_add(4);
            for relative in &missing_directories {
                let path_bytes = restore_journal_path_bytes(relative);
                let path_len = u32::try_from(path_bytes.len()).map_err(|_| {
                    LpmError::Task(format!(
                        "task cache restore directory path is too long for recovery: {}",
                        relative.display()
                    ))
                })?;
                journal_bytes = journal_bytes.saturating_add(4 + u64::from(path_len));
                if journal_bytes > MAX_RESTORE_JOURNAL_BYTES {
                    return Err(LpmError::Task(format!(
                        "task cache restore journal exceeds {MAX_RESTORE_JOURNAL_BYTES} bytes"
                    )));
                }
                writer.write_all(&path_len.to_le_bytes())?;
                writer.write_all(&path_bytes)?;
            }
            writer.flush()?;
            Ok(())
        },
    )?;
    Ok(existing_outputs)
}

fn analyze_restore_plan(
    project: &Dir,
    project_dir: &Path,
    files: &[PathBuf],
    install_count: usize,
) -> Result<(Vec<bool>, Vec<PathBuf>), LpmError> {
    let mut missing = HashSet::new();
    let mut existing_outputs = Vec::with_capacity(files.len());
    let mut cached_parent: Option<(PathBuf, Option<Dir>)> = None;

    for (index, relative) in files.iter().enumerate() {
        let parent_path = relative.parent().unwrap_or_else(|| Path::new(""));
        if cached_parent
            .as_ref()
            .is_none_or(|(cached_path, _)| cached_path != parent_path)
        {
            let mut current_path = PathBuf::new();
            let mut current_dir = Some(project.try_clone()?);
            for component in parent_path.components() {
                let Component::Normal(name) = component else {
                    return Err(LpmError::Task(format!(
                        "invalid task cache restore path: {}",
                        relative.display()
                    )));
                };
                current_path.push(name);
                if current_dir.is_none() || missing.contains(&current_path) {
                    current_dir = None;
                } else {
                    let parent = current_dir.as_ref().expect("restore parent is present");
                    match parent.open_dir_nofollow(name) {
                        Ok(next) => current_dir = Some(next),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            current_dir = None;
                        }
                        Err(error) => {
                            return Err(LpmError::Task(format!(
                                "task cache restore destination has an unsafe parent at {}: {error}",
                                project_dir.join(&current_path).display(),
                            )));
                        }
                    }
                }
                if current_dir.is_none()
                    && index < install_count
                    && missing.insert(current_path.clone())
                    && missing.len() > MAX_CACHE_ARCHIVE_ENTRIES
                {
                    return Err(LpmError::Task(format!(
                        "task cache restore journal exceeds directory-count cap ({MAX_CACHE_ARCHIVE_ENTRIES} entries)"
                    )));
                }
            }
            cached_parent = Some((parent_path.to_path_buf(), current_dir));
        }

        let name = relative.file_name().ok_or_else(|| {
            LpmError::Task(format!(
                "invalid empty task cache restore path: {}",
                relative.display()
            ))
        })?;
        let Some(parent) = cached_parent
            .as_ref()
            .and_then(|(_, parent)| parent.as_ref())
        else {
            existing_outputs.push(false);
            continue;
        };
        match parent.symlink_metadata(name) {
            Ok(metadata) if cap_metadata_is_link_or_reparse(&metadata) => {
                return Err(LpmError::Task(format!(
                    "task cache restore destination contains a symlink or junction: {}",
                    project_dir.join(relative).display()
                )));
            }
            Ok(metadata) if metadata.is_file() => existing_outputs.push(true),
            Ok(_) => {
                return Err(LpmError::Task(format!(
                    "task cache restore destination has an incompatible entry: {}",
                    project_dir.join(relative).display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing_outputs.push(false);
            }
            Err(error) => return Err(error.into()),
        }
    }

    let mut missing: Vec<_> = missing.into_iter().collect();
    missing.sort_unstable_by_key(|path| std::cmp::Reverse(path.components().count()));
    Ok((existing_outputs, missing))
}

struct RestoreRegistryRecord {
    dir: Dir,
    name: std::ffi::OsString,
    path: PathBuf,
}

fn restore_registry_record(
    root: &LpmRoot,
    canonical_project: &Path,
) -> Result<RestoreRegistryRecord, LpmError> {
    let (cache, cache_path) = open_cache_root(root, true)?.expect("created cache directory");
    let registry_dir = open_or_create_directory(
        &cache,
        RESTORE_REGISTRY_DIR,
        true,
        "task cache restore registry",
    )?
    .expect("created task cache restore registry");
    let registry_path = cache_path.join(RESTORE_REGISTRY_DIR);
    let mut hasher = Sha256::new();
    hash_path_identity(&mut hasher, canonical_project);
    let name = std::ffi::OsString::from(format!("{:x}.bin", hasher.finalize()));
    Ok(RestoreRegistryRecord {
        path: registry_path.join(&name),
        dir: registry_dir,
        name,
    })
}

#[cfg(test)]
fn write_restore_owner(
    restore_dir: &Path,
    token: &[u8; RESTORE_TOKEN_BYTES],
) -> Result<(), LpmError> {
    let restore = Dir::open_ambient_dir(restore_dir, cap_std::ambient_authority())?;
    write_restore_owner_open(&restore, token)
}

fn write_restore_owner_open(
    restore: &Dir,
    token: &[u8; RESTORE_TOKEN_BYTES],
) -> Result<(), LpmError> {
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
    let mut owner = restore.open_with(RESTORE_OWNER_NAME, &options)?.into_std();
    owner.write_all(RESTORE_OWNER_MAGIC)?;
    owner.write_all(token)?;
    set_open_file_permissions_restricted(&owner)?;
    owner.sync_all()?;
    sync_cap_directory(restore)?;
    Ok(())
}

#[cfg(test)]
fn write_restore_committed(staging: &Dir) -> Result<(), LpmError> {
    write_open_file_atomic_with(
        staging,
        std::ffi::OsStr::new(RESTORE_COMMITTED_NAME),
        |file| {
            file.write_all(RESTORE_COMMITTED_MAGIC)?;
            Ok(())
        },
    )
}

#[cfg(test)]
pub(super) fn write_restore_committed_for_test(restore_dir: &Path) -> Result<(), LpmError> {
    let staging = Dir::open_ambient_dir(restore_dir, cap_std::ambient_authority())?;
    write_restore_committed(&staging)
}

fn restore_is_committed(staging: &Dir, restore_dir: &Path) -> Result<bool, LpmError> {
    let Some(marker) = open_optional_regular_file(
        staging,
        std::ffi::OsStr::new(RESTORE_COMMITTED_NAME),
        "task cache restore commit marker",
    )?
    else {
        return Ok(false);
    };
    let marker_path = restore_dir.join(RESTORE_COMMITTED_NAME);
    let (bytes, metadata) = lpm_common::read_file_capped_from_open_file(
        marker.into_std(),
        &marker_path,
        RESTORE_COMMITTED_MAGIC.len() as u64,
    )?;
    if !metadata.is_file() || bytes != RESTORE_COMMITTED_MAGIC {
        return Err(LpmError::Task(format!(
            "invalid task cache restore commit marker: {}",
            marker_path.display()
        )));
    }
    Ok(true)
}

fn write_restore_registration(
    record: &RestoreRegistryRecord,
    restore_dir: &Path,
    token: &[u8; RESTORE_TOKEN_BYTES],
    committed: bool,
) -> Result<(), LpmError> {
    let staging_name = restore_dir.file_name().ok_or_else(|| {
        LpmError::Task(format!(
            "task cache restore directory has no name: {}",
            restore_dir.display()
        ))
    })?;
    let staging_path = Path::new(staging_name);
    let Some(Component::Normal(_)) = staging_path.components().next() else {
        return Err(LpmError::Task(
            "invalid task cache restore directory name".into(),
        ));
    };
    if staging_path.components().count() != 1 {
        return Err(LpmError::Task(
            "invalid task cache restore directory name".into(),
        ));
    }
    let name_bytes = restore_journal_path_bytes(staging_path);
    let name_len = u32::try_from(name_bytes.len())
        .map_err(|_| LpmError::Task("task cache restore directory name is too long".into()))?;
    let mut record_bytes = Vec::with_capacity(
        RESTORE_REGISTRY_MAGIC.len() + 1 + 4 + name_bytes.len() + RESTORE_TOKEN_BYTES,
    );
    record_bytes.extend_from_slice(RESTORE_REGISTRY_MAGIC);
    record_bytes.push(u8::from(committed));
    record_bytes.extend_from_slice(&name_len.to_le_bytes());
    record_bytes.extend_from_slice(&name_bytes);
    record_bytes.extend_from_slice(token);
    write_open_file_atomic_with(&record.dir, &record.name, |file| {
        file.write_all(&record_bytes)?;
        Ok(())
    })?;
    Ok(())
}

struct RestoreRegistration {
    staging_name: PathBuf,
    token: [u8; RESTORE_TOKEN_BYTES],
    committed: bool,
}

fn decode_restore_registration(bytes: &[u8]) -> Result<RestoreRegistration, LpmError> {
    let (mut cursor, committed) = if bytes.starts_with(RESTORE_REGISTRY_MAGIC) {
        let state = *bytes
            .get(RESTORE_REGISTRY_MAGIC.len())
            .ok_or_else(|| LpmError::Task("truncated task cache restore registry record".into()))?;
        let committed = match state {
            0 => false,
            1 => true,
            _ => {
                return Err(LpmError::Task(
                    "invalid task cache restore registry state".into(),
                ));
            }
        };
        (RESTORE_REGISTRY_MAGIC.len() + 1, committed)
    } else if bytes.starts_with(RESTORE_REGISTRY_MAGIC_V1) {
        (RESTORE_REGISTRY_MAGIC_V1.len(), false)
    } else {
        return Err(LpmError::Task(
            "invalid task cache restore registry record".into(),
        ));
    };
    let name_len = read_restore_journal_u32(bytes, &mut cursor)? as usize;
    let name_end = cursor.checked_add(name_len).ok_or_else(|| {
        LpmError::Task("invalid task cache restore registry record length".into())
    })?;
    let name_bytes = bytes
        .get(cursor..name_end)
        .ok_or_else(|| LpmError::Task("truncated task cache restore registry record".into()))?;
    cursor = name_end;
    let token_end = cursor.checked_add(RESTORE_TOKEN_BYTES).ok_or_else(|| {
        LpmError::Task("invalid task cache restore registry record length".into())
    })?;
    let token: [u8; RESTORE_TOKEN_BYTES] = bytes
        .get(cursor..token_end)
        .ok_or_else(|| LpmError::Task("truncated task cache restore registry record".into()))?
        .try_into()
        .expect("restore token length was checked");
    if token_end != bytes.len() {
        return Err(LpmError::Task(
            "task cache restore registry record has trailing data".into(),
        ));
    }
    let staging_name = restore_journal_path_from_bytes(name_bytes)?;
    let mut components = staging_name.components();
    let Some(Component::Normal(name)) = components.next() else {
        return Err(LpmError::Task(
            "invalid task cache restore directory name".into(),
        ));
    };
    if components.next().is_some() || !name.to_string_lossy().starts_with(RESTORE_TEMP_PREFIX) {
        return Err(LpmError::Task(
            "invalid task cache restore directory name".into(),
        ));
    }
    Ok(RestoreRegistration {
        staging_name,
        token,
        committed,
    })
}

fn remove_restore_registration(record: &RestoreRegistryRecord) -> Result<(), LpmError> {
    match record.dir.remove_file_or_symlink(&record.name) {
        Ok(()) => sync_cap_directory(&record.dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn register_restore_for_test(
    root: &LpmRoot,
    project_dir: &Path,
    restore_dir: &Path,
) -> Result<(), LpmError> {
    let canonical_project = std::fs::canonicalize(project_dir)?;
    let record = restore_registry_record(root, &canonical_project)?;
    let token = [0x5au8; RESTORE_TOKEN_BYTES];
    set_dir_permissions_restricted(restore_dir)?;
    write_restore_owner(restore_dir, &token)?;
    write_restore_registration(&record, restore_dir, &token, false)
}

#[cfg(test)]
pub(super) fn mark_restore_registration_committed_for_test(
    root: &LpmRoot,
    project_dir: &Path,
    restore_dir: &Path,
) -> Result<(), LpmError> {
    let canonical_project = std::fs::canonicalize(project_dir)?;
    let record = restore_registry_record(root, &canonical_project)?;
    write_restore_registration(&record, restore_dir, &[0x5au8; RESTORE_TOKEN_BYTES], true)
}

fn recover_interrupted_restore(
    project_dir: &Path,
    record: &RestoreRegistryRecord,
) -> Result<(), LpmError> {
    let record_file = match open_optional_regular_file(
        &record.dir,
        &record.name,
        "task cache restore registry record",
    ) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(()),
        Err(error) => {
            remove_restore_registration(record)?;
            return Err(error);
        }
    };
    let record_metadata = record_file.metadata()?;
    if record_metadata.len() > MAX_RESTORE_REGISTRY_BYTES {
        remove_restore_registration(record)?;
        return Err(LpmError::Task(format!(
            "task cache restore registry record exceeds {MAX_RESTORE_REGISTRY_BYTES} bytes"
        )));
    }
    let (record_bytes, _) = lpm_common::read_file_capped_from_open_file(
        record_file.into_std(),
        &record.path,
        MAX_RESTORE_REGISTRY_BYTES,
    )
    .map_err(|error| {
        LpmError::Task(format!(
            "failed to read task cache restore registry: {error}"
        ))
    })?;
    let registration = match decode_restore_registration(&record_bytes) {
        Ok(registration) => registration,
        Err(error) => {
            remove_restore_registration(record)?;
            return Err(error);
        }
    };
    let restore_dir = project_dir.join(&registration.staging_name);
    recover_registered_restore(
        project_dir,
        &restore_dir,
        record,
        &registration.token,
        registration.committed,
    )
}

fn recover_registered_restore(
    project_dir: &Path,
    restore_dir: &Path,
    record: &RestoreRegistryRecord,
    token: &[u8; RESTORE_TOKEN_BYTES],
    committed: bool,
) -> Result<(), LpmError> {
    let project = Dir::open_ambient_dir(project_dir, cap_std::ambient_authority())?;
    let staging_name = restore_dir.strip_prefix(project_dir).map_err(|_| {
        LpmError::Task(format!(
            "task cache restore directory is outside the project: {}",
            restore_dir.display()
        ))
    })?;
    if staging_name.components().count() != 1 {
        return Err(LpmError::Task(format!(
            "invalid task cache restore directory: {}",
            restore_dir.display()
        )));
    }
    let staging = match project.open_dir_nofollow(staging_name) {
        Ok(staging) => staging,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            remove_restore_registration(record)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if !restore_owner_matches_open(&staging, token)? {
        remove_restore_registration(record)?;
        return Ok(());
    }
    if committed || restore_is_committed(&staging, restore_dir)? {
        cleanup_open_staging(&project, staging_name, staging)?;
        remove_restore_registration(record)?;
        return Ok(());
    }
    let journal_path = restore_dir.join(RESTORE_JOURNAL_NAME);
    let journal_file = match open_cap_file_nofollow(&staging, Path::new(RESTORE_JOURNAL_NAME)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            cleanup_open_staging(&project, staging_name, staging)?;
            remove_restore_registration(record)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    let journal_len = journal_file.metadata()?.len();
    if journal_len > MAX_RESTORE_JOURNAL_BYTES {
        return Err(LpmError::Task(format!(
            "task cache restore journal exceeds {MAX_RESTORE_JOURNAL_BYTES} bytes: {}",
            restore_dir.display()
        )));
    }
    let (journal, metadata) = lpm_common::read_file_capped_from_open_file(
        journal_file.into_std(),
        &journal_path,
        MAX_RESTORE_JOURNAL_BYTES,
    )
    .map_err(|error| {
        LpmError::Task(format!(
            "failed to read task cache restore journal: {error}"
        ))
    })?;
    if !metadata.is_file() || lpm_common::is_symlink_or_junction(&metadata) {
        return Err(LpmError::Task(format!(
            "task cache restore journal is not a real file: {}",
            journal_path.display()
        )));
    }
    let journal = decode_restore_journal(&journal)?;
    let output = staging.open_dir_nofollow("outputs").map_err(|error| {
        LpmError::Task(format!(
            "task cache recovery output root is unsafe: {error}"
        ))
    })?;
    let backup = staging.open_dir_nofollow("backups").map_err(|error| {
        LpmError::Task(format!(
            "task cache recovery backup root is unsafe: {error}"
        ))
    })?;

    for (relative, had_existing) in journal.outputs.into_iter().rev() {
        let backup_entry = lookup_file_nofollow(&backup, &relative, "recovery backup")?;
        if let Some(backup_file) = backup_entry {
            #[cfg(test)]
            wait_for_cache_race_barrier(
                &RECOVERY_BACKUP_RACE_BARRIER,
                &restore_dir.join("backups").join(&relative),
            );
            let (destination_parent, destination_name) = open_or_create_parent_nofollow(
                &project,
                &relative,
                "recovery destination",
                DirectoryCreationDurability::Immediate,
            )?;
            match destination_parent.remove_file_or_symlink(&destination_name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            publish_verified_file(
                backup_file,
                &destination_parent,
                &destination_name,
                "task cache recovery backup",
            )?;
        } else if !had_existing
            && recovery_output_was_installed(&output, &project, &relative)?
            && let Some((destination_parent, destination_name)) =
                lookup_path_parent_nofollow(&project, &relative, "recovery destination")?
        {
            match destination_parent.remove_file_or_symlink(&destination_name) {
                Ok(()) => sync_cap_directory(&destination_parent)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    for relative in journal.initially_missing_directories {
        if let Some((parent, name)) =
            lookup_path_parent_nofollow(&project, &relative, "recovery directory")?
        {
            match parent.remove_dir(name) {
                Ok(()) => sync_cap_directory(&parent)?,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    cleanup_open_staging(&project, staging_name, staging)?;
    remove_restore_registration(record)?;
    Ok(())
}

fn recovery_output_was_installed(
    output: &Dir,
    project: &Dir,
    relative: &Path,
) -> Result<bool, LpmError> {
    let Some(staged) = lookup_file_nofollow(output, relative, "recovery output")? else {
        return Ok(true);
    };
    let Some(destination) = lookup_file_nofollow(project, relative, "recovery destination")? else {
        return Ok(false);
    };
    let staged_identity = same_file::Handle::from_file(staged.into_std())?;
    let destination_identity = same_file::Handle::from_file(destination.into_std())?;
    Ok(staged_identity == destination_identity)
}

fn cleanup_open_staging(project: &Dir, staging_name: &Path, staging: Dir) -> Result<(), LpmError> {
    #[cfg(test)]
    {
        let mut failure = STAGING_CLEANUP_FAILURE
            .lock()
            .expect("staging cleanup failure lock");
        if failure.as_deref() == staging_name.file_name() {
            failure.take();
            return Err(LpmError::Task(format!(
                "failed to clean task cache restore staging directory {}: injected failure",
                staging_name.display()
            )));
        }
    }
    clean_open_cache_ephemeral(&staging)?;
    drop(staging);
    match project.remove_dir(staging_name) {
        Ok(()) => sync_cap_directory(project)?,
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

fn restore_owner_matches_open(
    staging: &Dir,
    token: &[u8; RESTORE_TOKEN_BYTES],
) -> Result<bool, LpmError> {
    let owner = match open_cap_file_nofollow(staging, Path::new(RESTORE_OWNER_NAME)) {
        Ok(owner) => owner,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let expected_len = RESTORE_OWNER_MAGIC.len() + RESTORE_TOKEN_BYTES;
    let (owner, metadata) = lpm_common::read_file_capped_from_open_file(
        owner.into_std(),
        Path::new(RESTORE_OWNER_NAME),
        expected_len as u64,
    )
    .map_err(|error| LpmError::Task(format!("failed to read task cache restore owner: {error}")))?;
    Ok(metadata.is_file()
        && !lpm_common::is_symlink_or_junction(&metadata)
        && owner.len() == expected_len
        && owner.starts_with(RESTORE_OWNER_MAGIC)
        && owner[RESTORE_OWNER_MAGIC.len()..] == token[..])
}

fn open_cap_file_nofollow(
    root: &Dir,
    relative: &Path,
) -> Result<cap_std::fs::File, std::io::Error> {
    let (parent, name) = open_existing_parent_nofollow(root, relative, "restore file")
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    parent.open_with(name, &options)
}

fn open_optional_regular_file(
    parent: &Dir,
    name: &std::ffi::OsStr,
    label: &str,
) -> Result<Option<cap_std::fs::File>, LpmError> {
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = match parent.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(LpmError::Task(format!(
                "failed to open {label} without following links: {error}"
            )));
        }
    };
    if !file.metadata()?.is_file() {
        return Err(LpmError::Task(format!("{label} is not a real file")));
    }
    Ok(Some(file))
}

#[derive(Clone, Copy)]
enum DirectoryCreationDurability {
    Immediate,
    Deferred,
}

fn publish_verified_file(
    source: cap_std::fs::File,
    destination_parent: &Dir,
    destination_name: &std::ffi::OsStr,
    label: &str,
) -> Result<(), LpmError> {
    use std::io::{Read as _, Seek as _, Write as _};

    let mut source = source.into_std();
    let metadata = source.metadata()?;
    if !metadata.is_file() {
        return Err(LpmError::Task(format!("{label} is not a real file")));
    }
    source.rewind()?;
    let (temporary_name, temporary) = create_private_restore_file(destination_parent)?;
    let mut temporary = temporary.into_std();
    let result = (|| {
        let size = metadata.len();
        {
            let mut limited = (&mut source).take(size);
            std::io::copy(&mut limited, &mut temporary)?;
            if limited.limit() != 0 {
                return Err(LpmError::Task(format!(
                    "{label} became shorter while it was copied"
                )));
            }
        }
        let mut extra = [0u8; 1];
        if source.read(&mut extra)? != 0 || source.metadata()?.len() != size {
            return Err(LpmError::Task(format!(
                "{label} changed size while it was copied"
            )));
        }
        temporary.set_times(std::fs::FileTimes::new().set_modified(metadata.modified()?))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            temporary.set_permissions(std::fs::Permissions::from_mode(
                metadata.permissions().mode() & 0o777,
            ))?;
        }
        temporary.flush()?;
        sync_restore_file(&temporary)?;
        drop(temporary);
        destination_parent.rename(
            Path::new(&temporary_name),
            destination_parent,
            Path::new(destination_name),
        )?;
        sync_cap_directory(destination_parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = destination_parent.remove_file_or_symlink(&temporary_name);
    }
    result
}

fn publish_staged_file(
    source: cap_std::fs::File,
    source_parent: &Dir,
    source_name: &Path,
    destination_parent: &Dir,
    destination_name: &std::ffi::OsStr,
) -> Result<(), LpmError> {
    use std::io::{Read as _, Seek as _, Write as _};

    let mut source = source.into_std();
    let metadata = source.metadata()?;
    source.rewind()?;
    let (temporary_name, temporary) = create_private_restore_file(destination_parent)?;
    let mut temporary = temporary.into_std();
    let result = (|| {
        let size = metadata.len();
        {
            let mut limited = (&mut source).take(size);
            std::io::copy(&mut limited, &mut temporary)?;
            if limited.limit() != 0 {
                return Err(LpmError::Task(
                    "staged task cache output became shorter while it was copied".into(),
                ));
            }
        }
        let mut extra = [0u8; 1];
        if source.read(&mut extra)? != 0 || source.metadata()?.len() != size {
            return Err(LpmError::Task(
                "staged task cache output changed size while it was copied".into(),
            ));
        }
        temporary.set_times(std::fs::FileTimes::new().set_modified(metadata.modified()?))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            temporary.set_permissions(std::fs::Permissions::from_mode(
                metadata.permissions().mode() & 0o777,
            ))?;
        }
        temporary.flush()?;
        sync_restore_file(&temporary)?;
        let temporary_identity = same_file::Handle::from_file(temporary.try_clone()?)?;
        drop(temporary);
        match source_parent.remove_file_or_symlink(source_name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        destination_parent.hard_link(Path::new(&temporary_name), source_parent, source_name)?;
        let receipt = open_optional_regular_file(
            source_parent,
            source_name.as_os_str(),
            "task cache restore publication receipt",
        )?
        .ok_or_else(|| {
            LpmError::Task("task cache restore publication receipt disappeared".into())
        })?;
        if same_file::Handle::from_file(receipt.into_std())? != temporary_identity {
            return Err(LpmError::Task(
                "task cache restore publication receipt changed while it was created".into(),
            ));
        }
        sync_cap_directory(source_parent)?;
        match rename_staged_file_noreplace(
            destination_parent,
            Path::new(&temporary_name),
            destination_parent,
            destination_name,
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(LpmError::Task(format!(
                    "task cache output appeared during publication: {}",
                    destination_name.to_string_lossy()
                )));
            }
            Err(error) => return Err(error.into()),
        }
        sync_cap_directory(destination_parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = destination_parent.remove_file_or_symlink(&temporary_name);
    }
    result
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn rename_staged_file_noreplace(
    source_parent: &Dir,
    source_name: &Path,
    destination_parent: &Dir,
    destination_name: &std::ffi::OsStr,
) -> Result<(), std::io::Error> {
    use rustix::fs::{RenameFlags, renameat_with};

    renameat_with(
        source_parent,
        source_name,
        destination_parent,
        Path::new(destination_name),
        RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
}

#[cfg(windows)]
fn rename_staged_file_noreplace(
    source_parent: &Dir,
    source_name: &Path,
    destination_parent: &Dir,
    destination_name: &std::ffi::OsStr,
) -> Result<(), std::io::Error> {
    source_parent.rename(source_name, destination_parent, Path::new(destination_name))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn rename_staged_file_noreplace(
    source_parent: &Dir,
    source_name: &Path,
    _destination_parent: &Dir,
    _destination_name: &std::ffi::OsStr,
) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "atomic task cache publication is unsupported for {}",
            source_parent
                .metadata(source_name)
                .map(|_| source_name.display().to_string())
                .unwrap_or_else(|_| "staged output".into())
        ),
    ))
}

fn create_private_restore_file(directory: &Dir) -> Result<(String, cap_std::fs::File), LpmError> {
    use std::fmt::Write as _;

    let mut last_collision = None;
    for _ in 0..32 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|error| {
            LpmError::Task(format!("failed to create restore temporary name: {error}"))
        })?;
        let mut name = String::with_capacity(51);
        name.push_str(".lpm-cache-publish-");
        for byte in random {
            write!(name, "{byte:02x}").expect("writing to a String cannot fail");
        }
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
        match directory.open_with(&name, &options) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(last_collision
        .unwrap_or_else(|| std::io::Error::other("could not create restore temporary file"))
        .into())
}

fn write_open_file_atomic_with<T>(
    directory: &Dir,
    destination_name: &std::ffi::OsStr,
    write: impl FnOnce(&mut std::fs::File) -> Result<T, LpmError>,
) -> Result<T, LpmError> {
    let (temporary_name, temporary) = create_private_restore_file(directory)?;
    let mut temporary = temporary.into_std();
    let result = (|| {
        let output = write(&mut temporary)?;
        set_open_file_permissions_restricted(&temporary)?;
        temporary.sync_all()?;
        drop(temporary);
        directory.rename(
            Path::new(&temporary_name),
            directory,
            Path::new(destination_name),
        )?;
        sync_cap_directory(directory)?;
        Ok(output)
    })();
    if result.is_err() {
        let _ = directory.remove_file_or_symlink(&temporary_name);
    }
    result
}

fn lookup_file_nofollow(
    root: &Dir,
    relative: &Path,
    label: &str,
) -> Result<Option<cap_std::fs::File>, LpmError> {
    let Some((parent, name)) = lookup_path_parent_nofollow(root, relative, label)? else {
        return Ok(None);
    };
    open_optional_regular_file(&parent, &name, &format!("task cache {label}"))
        .map_err(|error| LpmError::Task(format!("{error}: {}", relative.display())))
}

fn lookup_path_parent_nofollow(
    root: &Dir,
    relative: &Path,
    label: &str,
) -> Result<Option<(Dir, std::ffi::OsString)>, LpmError> {
    let mut components = relative.components().peekable();
    let mut parent = root.try_clone()?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid task cache {label} path: {}",
                relative.display()
            )));
        };
        if components.peek().is_none() {
            return Ok(Some((parent, name.to_os_string())));
        }
        match parent.open_dir_nofollow(name) {
            Ok(next) => parent = next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(LpmError::Task(format!(
                    "task cache {label} parent is unsafe at {}: {error}",
                    relative.display()
                )));
            }
        }
    }
    Err(LpmError::Task(format!(
        "invalid empty task cache {label} path"
    )))
}

struct RestoreJournal {
    outputs: Vec<(PathBuf, bool)>,
    initially_missing_directories: Vec<PathBuf>,
}

fn decode_restore_journal(bytes: &[u8]) -> Result<RestoreJournal, LpmError> {
    if !bytes.starts_with(RESTORE_JOURNAL_MAGIC) {
        return Err(LpmError::Task("invalid task cache restore journal".into()));
    }
    let mut cursor = RESTORE_JOURNAL_MAGIC.len();
    let count = read_restore_journal_u32(bytes, &mut cursor)? as usize;
    if count > MAX_CACHE_ARCHIVE_ENTRIES {
        return Err(LpmError::Task(format!(
            "task cache restore journal exceeds entry-count cap ({MAX_CACHE_ARCHIVE_ENTRIES} entries)"
        )));
    }
    let mut outputs = Vec::with_capacity(count);
    let mut output_paths = HashSet::with_capacity(count);
    for _ in 0..count {
        let had_existing = match bytes.get(cursor) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(LpmError::Task("invalid task cache restore journal".into())),
        };
        cursor += 1;
        let path_len = read_restore_journal_u32(bytes, &mut cursor)? as usize;
        let path_end = cursor.checked_add(path_len).ok_or_else(|| {
            LpmError::Task("invalid task cache restore journal path length".into())
        })?;
        let path_bytes = bytes
            .get(cursor..path_end)
            .ok_or_else(|| LpmError::Task("truncated task cache restore journal".into()))?;
        cursor = path_end;
        let relative = restore_journal_path_from_bytes(path_bytes)?;
        let relative = normalize_archive_path(&relative, "task cache restore journal")?;
        if !output_paths.insert(relative.clone()) {
            return Err(LpmError::Task(format!(
                "task cache restore journal contains duplicate output: {}",
                relative.display()
            )));
        }
        outputs.push((relative, had_existing));
    }
    let directory_count = read_restore_journal_u32(bytes, &mut cursor)? as usize;
    if directory_count > MAX_CACHE_ARCHIVE_ENTRIES {
        return Err(LpmError::Task(format!(
            "task cache restore journal exceeds directory-count cap ({MAX_CACHE_ARCHIVE_ENTRIES} entries)"
        )));
    }
    let mut initially_missing_directories = Vec::with_capacity(directory_count);
    let mut directory_paths = HashSet::with_capacity(directory_count);
    for _ in 0..directory_count {
        let path_len = read_restore_journal_u32(bytes, &mut cursor)? as usize;
        let path_end = cursor.checked_add(path_len).ok_or_else(|| {
            LpmError::Task("invalid task cache restore journal path length".into())
        })?;
        let path_bytes = bytes
            .get(cursor..path_end)
            .ok_or_else(|| LpmError::Task("truncated task cache restore journal".into()))?;
        cursor = path_end;
        let relative = restore_journal_path_from_bytes(path_bytes)?;
        let relative = normalize_archive_path(&relative, "task cache restore journal")?;
        if !directory_paths.insert(relative.clone()) {
            return Err(LpmError::Task(format!(
                "task cache restore journal contains duplicate directory: {}",
                relative.display()
            )));
        }
        initially_missing_directories.push(relative);
    }
    if cursor != bytes.len() {
        return Err(LpmError::Task(
            "task cache restore journal has trailing data".into(),
        ));
    }
    initially_missing_directories
        .sort_unstable_by_key(|path| std::cmp::Reverse(path.components().count()));
    Ok(RestoreJournal {
        outputs,
        initially_missing_directories,
    })
}

fn read_restore_journal_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, LpmError> {
    let end = cursor
        .checked_add(4)
        .ok_or_else(|| LpmError::Task("invalid task cache restore journal".into()))?;
    let encoded: [u8; 4] = bytes
        .get(*cursor..end)
        .ok_or_else(|| LpmError::Task("truncated task cache restore journal".into()))?
        .try_into()
        .expect("journal length was checked");
    *cursor = end;
    Ok(u32::from_le_bytes(encoded))
}

#[cfg(unix)]
fn restore_journal_path_bytes(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt;
    std::borrow::Cow::Borrowed(path.as_os_str().as_bytes())
}

#[cfg(windows)]
fn restore_journal_path_bytes(path: &Path) -> std::borrow::Cow<'_, [u8]> {
    use std::os::windows::ffi::OsStrExt;
    let mut bytes = Vec::new();
    for unit in path.as_os_str().encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    std::borrow::Cow::Owned(bytes)
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Windows implementation rejects malformed UTF-16 path bytes"
)]
fn restore_journal_path_from_bytes(bytes: &[u8]) -> Result<PathBuf, LpmError> {
    use std::os::unix::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
}

#[cfg(windows)]
fn restore_journal_path_from_bytes(bytes: &[u8]) -> Result<PathBuf, LpmError> {
    use std::os::windows::ffi::OsStringExt;
    if !bytes.len().is_multiple_of(2) {
        return Err(LpmError::Task(
            "invalid Windows path in task cache restore journal".into(),
        ));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&units)))
}

fn create_directory_path_nofollow(
    root: &Dir,
    relative: &Path,
    label: &str,
) -> Result<(), LpmError> {
    let mut current = root.try_clone()?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid task cache {label} path: {}",
                relative.display()
            )));
        };
        match current.open_dir_nofollow(name) {
            Ok(next) => current = next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current.create_dir(name)?;
                current = current.open_dir_nofollow(name)?;
            }
            Err(error) => {
                return Err(LpmError::Task(format!(
                    "task cache {label} path conflicts at {}: {error}",
                    relative.display()
                )));
            }
        }
    }
    Ok(())
}

pub(super) struct RestoreTransaction {
    project_dir: PathBuf,
    project: Dir,
    output: Dir,
    backup: Dir,
    project_parent: Option<CachedRestoreDirectory>,
    output_parent: Option<CachedRestoreDirectory>,
    installed: Vec<AppliedOutput>,
    installed_trees: Vec<PathBuf>,
    created_dirs: Vec<PathBuf>,
    mutated_dirs: HashSet<PathBuf>,
    committed: bool,
}

struct CachedRestoreDirectory {
    relative: PathBuf,
    dir: Dir,
}

struct AppliedOutput {
    relative: PathBuf,
    backed_up: bool,
    installed: bool,
}

impl RestoreTransaction {
    #[cfg(test)]
    pub(super) fn new(
        project_dir: PathBuf,
        restore_dir: &Path,
        output_count: usize,
    ) -> Result<Self, LpmError> {
        let project = Dir::open_ambient_dir(&project_dir, cap_std::ambient_authority())?;
        let staging_name = restore_dir.strip_prefix(&project_dir).map_err(|_| {
            LpmError::Task(format!(
                "task cache restore staging directory is outside the project: {}",
                restore_dir.display()
            ))
        })?;
        if staging_name.components().count() != 1 {
            return Err(LpmError::Task(format!(
                "invalid task cache restore staging directory: {}",
                restore_dir.display()
            )));
        }
        let staging = project.open_dir_nofollow(staging_name)?;
        Self::new_with_open_staging(project_dir, project, &staging, output_count)
    }

    fn new_with_open_staging(
        project_dir: PathBuf,
        project: Dir,
        staging: &Dir,
        output_count: usize,
    ) -> Result<Self, LpmError> {
        let output = staging.open_dir_nofollow("outputs")?;
        let backup = staging.open_dir_nofollow("backups")?;
        Ok(Self {
            project_dir,
            project,
            output,
            backup,
            project_parent: None,
            output_parent: None,
            installed: Vec::with_capacity(output_count),
            installed_trees: Vec::new(),
            created_dirs: Vec::with_capacity(output_count.min(64)),
            mutated_dirs: HashSet::with_capacity(output_count.min(64)),
            committed: false,
        })
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(super) fn install_missing_top_level_trees(
        &mut self,
        files: &[PathBuf],
    ) -> Result<HashSet<std::ffi::OsString>, LpmError> {
        use rustix::fs::{RenameFlags, renameat_with};

        let mut candidates = HashSet::new();
        for relative in files {
            let mut components = relative.components();
            let Some(Component::Normal(root)) = components.next() else {
                continue;
            };
            if components.next().is_some() {
                candidates.insert(root.to_os_string());
            }
        }
        let mut candidates: Vec<_> = candidates.into_iter().collect();
        candidates.sort_unstable();

        let mut installed = HashSet::with_capacity(candidates.len());
        for root in candidates {
            match self.project.symlink_metadata(&root) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => continue,
                Err(error) => return Err(error.into()),
            }
            let source = self.output.open_dir_nofollow(&root).map_err(|error| {
                LpmError::Task(format!(
                    "staged task cache output tree is unsafe at {}: {error}",
                    Path::new(&root).display()
                ))
            })?;
            let expected = same_file::Handle::from_file(source.try_clone()?.into_std_file())?;
            #[cfg(test)]
            wait_for_cache_race_barrier(&STAGED_TREE_RACE_BARRIER, &self.project_dir.join(&root));
            match renameat_with(
                &self.output,
                Path::new(&root),
                &self.project,
                Path::new(&root),
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        std::io::Error::from(error).kind(),
                        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
            let destination = match self.project.open_dir_nofollow(&root) {
                Ok(destination) => destination,
                Err(error) => {
                    let _ = self.project.remove_file_or_symlink(&root);
                    let _ = sync_cap_directory(&self.project);
                    return Err(LpmError::Task(format!(
                        "task cache output tree changed during publication at {}: {error}",
                        self.project_dir.join(&root).display()
                    )));
                }
            };
            let actual = same_file::Handle::from_file(destination.try_clone()?.into_std_file())?;
            if actual != expected {
                drop(actual);
                drop(expected);
                clean_open_cache_ephemeral(&destination)?;
                drop(destination);
                self.project.remove_dir(&root)?;
                sync_cap_directory(&self.project)?;
                return Err(LpmError::Task(format!(
                    "staged task cache output tree changed during publication at {}",
                    self.project_dir.join(&root).display()
                )));
            }
            self.installed_trees.push(PathBuf::from(&root));
            installed.insert(root);
        }
        if !installed.is_empty() {
            self.mutated_dirs.insert(PathBuf::new());
        }
        Ok(installed)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub(super) fn install_missing_top_level_trees(
        &mut self,
        _files: &[PathBuf],
    ) -> Result<HashSet<std::ffi::OsString>, LpmError> {
        Ok(HashSet::new())
    }

    pub(super) fn install(&mut self, relative: &Path, had_existing: bool) -> Result<(), LpmError> {
        let destination_parent_path = relative.parent().unwrap_or_else(|| Path::new(""));
        let destination_name = relative.file_name().ok_or_else(|| {
            LpmError::Task(format!(
                "invalid empty task cache restore path: {}",
                relative.display()
            ))
        })?;
        self.ensure_project_parent(destination_parent_path, true)?;
        self.ensure_output_parent(destination_parent_path)?;
        let destination_parent = &self
            .project_parent
            .as_ref()
            .expect("project restore parent was opened")
            .dir;
        let output_parent = &self
            .output_parent
            .as_ref()
            .expect("staged output parent was opened")
            .dir;
        let destination = self.project_dir.join(relative);
        #[cfg(test)]
        wait_for_cache_race_barrier(&RESTORE_RACE_BARRIER, &destination);
        let existing = open_optional_regular_file(
            destination_parent,
            destination_name,
            "task cache restore destination",
        )?;
        let has_existing_now = existing.is_some();
        if has_existing_now != had_existing {
            return Err(LpmError::Task(format!(
                "task cache restore destination changed during restore: {}",
                destination.display()
            )));
        }
        self.installed.push(AppliedOutput {
            relative: relative.to_path_buf(),
            backed_up: false,
            installed: false,
        });
        let applied = self.installed.last_mut().expect("output record was added");
        if let Some(existing) = existing {
            let (backup_parent, backup_name) = open_or_create_parent_nofollow(
                &self.backup,
                relative,
                "restore backup",
                DirectoryCreationDurability::Immediate,
            )?;
            publish_verified_file(
                existing,
                &backup_parent,
                &backup_name,
                "task cache restore backup source",
            )?;
            applied.backed_up = true;
            #[cfg(test)]
            fail_after_first_backup_sync(&self.project_dir, relative)?;
            destination_parent.remove_file_or_symlink(destination_name)?;
            sync_cap_directory(destination_parent)?;
        }
        let output_file = open_optional_regular_file(
            output_parent,
            destination_name,
            "staged task cache output",
        )?
        .ok_or_else(|| {
            LpmError::Task(format!(
                "staged task cache output disappeared: {}",
                relative.display()
            ))
        })?;
        #[cfg(test)]
        wait_for_cache_race_barrier(
            &STAGED_OUTPUT_RACE_BARRIER,
            &self.project_dir.join(relative),
        );
        publish_staged_file(
            output_file,
            output_parent,
            Path::new(destination_name),
            destination_parent,
            destination_name,
        )?;
        #[cfg(test)]
        wait_for_cache_race_barrier(
            &PUBLISHED_OUTPUT_RACE_BARRIER,
            &self.project_dir.join(relative),
        );
        applied.installed = true;
        self.mutated_dirs
            .insert(destination_parent_path.to_path_buf());
        Ok(())
    }

    fn remove(&mut self, relative: &Path, had_existing: bool) -> Result<(), LpmError> {
        let destination_parent_path = relative.parent().unwrap_or_else(|| Path::new(""));
        let destination_name = relative.file_name().ok_or_else(|| {
            LpmError::Task(format!(
                "invalid empty task cache restore path: {}",
                relative.display()
            ))
        })?;
        self.ensure_project_parent(destination_parent_path, false)?;
        let destination_parent = &self
            .project_parent
            .as_ref()
            .expect("project restore parent was opened")
            .dir;
        let destination = self.project_dir.join(relative);
        let existing = open_optional_regular_file(
            destination_parent,
            destination_name,
            "task cache restore destination",
        )?;
        let has_existing_now = existing.is_some();
        if has_existing_now != had_existing {
            return Err(LpmError::Task(format!(
                "task cache restore destination changed during restore: {}",
                destination.display()
            )));
        }
        self.installed.push(AppliedOutput {
            relative: relative.to_path_buf(),
            backed_up: false,
            installed: false,
        });
        let applied = self.installed.last_mut().expect("output record was added");
        if let Some(existing) = existing {
            let (backup_parent, backup_name) = open_or_create_parent_nofollow(
                &self.backup,
                relative,
                "restore backup",
                DirectoryCreationDurability::Immediate,
            )?;
            publish_verified_file(
                existing,
                &backup_parent,
                &backup_name,
                "task cache restore backup source",
            )?;
            applied.backed_up = true;
            #[cfg(test)]
            fail_after_first_backup_sync(&self.project_dir, relative)?;
            destination_parent.remove_file_or_symlink(destination_name)?;
            sync_cap_directory(destination_parent)?;
        }
        self.mutated_dirs
            .insert(destination_parent_path.to_path_buf());
        Ok(())
    }

    fn ensure_project_parent(&mut self, parent_path: &Path, create: bool) -> Result<(), LpmError> {
        if self
            .project_parent
            .as_ref()
            .is_some_and(|cached| cached.relative == parent_path)
        {
            return Ok(());
        }
        let mut parent = self.project.try_clone()?;
        let mut current_path = PathBuf::new();
        for component in parent_path.components() {
            let Component::Normal(name) = component else {
                return Err(LpmError::Task(format!(
                    "invalid task cache restore path: {}",
                    parent_path.display()
                )));
            };
            current_path.push(name);
            match parent.open_dir_nofollow(name) {
                Ok(next) => parent = next,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                    parent.create_dir(name)?;
                    self.created_dirs.push(current_path.clone());
                    match parent.open_dir_nofollow(name) {
                        Ok(next) => parent = next,
                        Err(error) => {
                            self.created_dirs.pop();
                            return Err(error.into());
                        }
                    }
                }
                Err(error) => {
                    return Err(LpmError::Task(format!(
                        "task cache restore destination has an unsafe parent at {}: {error}",
                        self.project_dir.join(&current_path).display()
                    )));
                }
            }
        }
        self.project_parent = Some(CachedRestoreDirectory {
            relative: parent_path.to_path_buf(),
            dir: parent,
        });
        Ok(())
    }

    fn ensure_output_parent(&mut self, parent_path: &Path) -> Result<(), LpmError> {
        if self
            .output_parent
            .as_ref()
            .is_some_and(|cached| cached.relative == parent_path)
        {
            return Ok(());
        }
        self.output_parent = Some(CachedRestoreDirectory {
            relative: parent_path.to_path_buf(),
            dir: open_directory_nofollow(&self.output, parent_path, "staged output")?,
        });
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn commit(&mut self) -> Result<(), LpmError> {
        self.prepare_commit()?;
        self.mark_committed();
        Ok(())
    }

    fn prepare_commit(&self) -> Result<(), LpmError> {
        for relative in &self.mutated_dirs {
            let directory = open_directory_nofollow(&self.project, relative, "restore output")?;
            sync_cap_directory(&directory)?;
        }
        Ok(())
    }

    fn mark_committed(&mut self) {
        self.committed = true;
    }

    pub(super) fn rollback_error(&mut self, original: LpmError) -> (LpmError, bool) {
        match self.rollback() {
            Ok(()) => (original, false),
            Err(rollback) => {
                self.committed = true;
                (
                    LpmError::Task(format!(
                        "task cache restore failed: {original}; rollback also failed: {rollback}"
                    )),
                    true,
                )
            }
        }
    }

    fn rollback(&mut self) -> Result<(), LpmError> {
        self.project_parent = None;
        self.output_parent = None;
        let mut first_error: Option<std::io::Error> = None;
        for applied in self.installed.iter().rev() {
            let destination_parent =
                open_existing_parent_nofollow(&self.project, &applied.relative, "restore output");
            let Ok((destination_parent, destination_name)) = destination_parent else {
                if first_error.is_none() {
                    first_error = Some(std::io::Error::other(
                        "failed to reopen task cache restore destination",
                    ));
                }
                continue;
            };
            if applied.installed
                && let Err(error) = destination_parent.remove_file_or_symlink(&destination_name)
                && error.kind() != std::io::ErrorKind::NotFound
                && first_error.is_none()
            {
                first_error = Some(error);
            }
            if applied.backed_up {
                match destination_parent.remove_file_or_symlink(&destination_name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) if first_error.is_none() => first_error = Some(error),
                    Err(_) => {}
                }
                match open_cap_file_nofollow(&self.backup, &applied.relative) {
                    Ok(backup) => {
                        if let Err(error) = publish_verified_file(
                            backup,
                            &destination_parent,
                            &destination_name,
                            "task cache restore backup",
                        ) && first_error.is_none()
                        {
                            first_error = Some(std::io::Error::other(error.to_string()));
                        }
                    }
                    Err(error) if first_error.is_none() => {
                        first_error = Some(error);
                    }
                    Err(_) => {}
                }
            }
            if !applied.backed_up
                && let Err(error) = sync_cap_directory(&destination_parent)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        let mut removed_tree = false;
        for relative in self.installed_trees.iter().rev() {
            let tree = match self.project.open_dir_nofollow(relative) {
                Ok(tree) => tree,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    continue;
                }
            };
            if let Err(error) = clean_open_cache_ephemeral(&tree) {
                if first_error.is_none() {
                    first_error = Some(std::io::Error::other(error.to_string()));
                }
                continue;
            }
            drop(tree);
            match self.project.remove_dir(relative) {
                Ok(()) => removed_tree = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if removed_tree
            && let Err(error) = sync_cap_directory(&self.project)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        for directory in self.created_dirs.iter().rev() {
            match open_existing_parent_nofollow(&self.project, directory, "restore directory") {
                Ok((parent, name)) => {
                    if let Err(error) = parent.remove_dir(name)
                        && error.kind() != std::io::ErrorKind::NotFound
                        && first_error.is_none()
                    {
                        first_error = Some(error);
                    }
                    if let Err(error) = sync_cap_directory(&parent)
                        && first_error.is_none()
                    {
                        first_error = Some(error);
                    }
                }
                Err(_) if first_error.is_none() => {
                    first_error = Some(std::io::Error::other(
                        "failed to reopen task cache restore directory",
                    ));
                }
                Err(_) => {}
            }
        }
        if let Some(error) = first_error {
            return Err(error.into());
        }
        self.installed.clear();
        self.installed_trees.clear();
        self.created_dirs.clear();
        self.mutated_dirs.clear();
        Ok(())
    }
}

fn open_directory_nofollow(root: &Dir, relative: &Path, label: &str) -> Result<Dir, LpmError> {
    let mut current = root.try_clone()?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid task cache {label} directory: {}",
                relative.display()
            )));
        };
        current = current.open_dir_nofollow(name).map_err(|error| {
            LpmError::Task(format!(
                "task cache {label} directory is unsafe at {}: {error}",
                relative.display()
            ))
        })?;
    }
    Ok(current)
}

fn open_existing_parent_nofollow(
    root: &Dir,
    relative: &Path,
    label: &str,
) -> Result<(Dir, std::ffi::OsString), LpmError> {
    let mut components = relative.components().peekable();
    let mut parent = root.try_clone()?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid task cache {label} path: {}",
                relative.display()
            )));
        };
        if components.peek().is_none() {
            return Ok((parent, name.to_os_string()));
        }
        parent = parent.open_dir_nofollow(name).map_err(|error| {
            LpmError::Task(format!(
                "task cache {label} parent is unsafe at {}: {error}",
                relative.display()
            ))
        })?;
    }
    Err(LpmError::Task(format!(
        "invalid empty task cache {label} path"
    )))
}

fn open_or_create_parent_nofollow(
    root: &Dir,
    relative: &Path,
    label: &str,
    durability: DirectoryCreationDurability,
) -> Result<(Dir, std::ffi::OsString), LpmError> {
    let mut components = relative.components().peekable();
    let mut parent = root.try_clone()?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(LpmError::Task(format!(
                "invalid task cache {label} path: {}",
                relative.display()
            )));
        };
        if components.peek().is_none() {
            return Ok((parent, name.to_os_string()));
        }
        match parent.open_dir_nofollow(name) {
            Ok(next) => parent = next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                parent.create_dir(name)?;
                if matches!(durability, DirectoryCreationDurability::Immediate) {
                    sync_cap_directory(&parent)?;
                }
                parent = parent.open_dir_nofollow(name)?;
            }
            Err(error) => {
                return Err(LpmError::Task(format!(
                    "task cache {label} parent is unsafe at {}: {error}",
                    relative.display()
                )));
            }
        }
    }
    Err(LpmError::Task(format!(
        "invalid empty task cache {label} path"
    )))
}

fn sync_cap_directory(directory: &Dir) -> Result<(), std::io::Error> {
    record_restore_durability_sync();
    sync_directory_handle(directory)
}

fn sync_restore_file(file: &std::fs::File) -> Result<(), std::io::Error> {
    record_restore_durability_sync();
    file.sync_all()
}

#[cfg(test)]
fn fail_after_first_backup_sync(project_dir: &Path, relative: &Path) -> Result<(), LpmError> {
    let failure = BACKUP_SYNC_FAILURE
        .lock()
        .expect("backup sync failure lock")
        .clone();
    if failure.is_some_and(|failure| failure.project == project_dir && failure.relative == relative)
    {
        return Err(LpmError::Task(format!(
            "failed to sync task cache backup {}: injected failure",
            relative.display()
        )));
    }
    Ok(())
}

impl Drop for RestoreTransaction {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.rollback();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_restore_rejects_paths_deeper_than_256_components_before_staging() {
        use std::io::Write as _;

        let root_dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(root_dir.path());
        let project = tempfile::tempdir().unwrap();
        let archive_path = root_dir.path().join("deep.tar.gz");
        let archive_file = std::fs::File::create(&archive_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(archive_file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut path = String::new();
        path.push_str(&"a/".repeat(256));
        path.push_str("file.txt");
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, &path, std::io::empty())
            .unwrap();
        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap().flush().unwrap();

        let archive = std::fs::File::open(&archive_path).unwrap();
        let error = match stage_cache_archive(&root, archive, project.path(), "task cache archive")
        {
            Ok(_) => panic!("an excessively deep archive path was accepted"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("nesting"),
            "expected nesting-depth limit error, got: {error}"
        );
        assert!(
            std::fs::read_dir(project.path()).unwrap().next().is_none(),
            "rejected restore created project output"
        );
    }

    fn append_journal_path(bytes: &mut Vec<u8>, path: &[u8]) {
        bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
        bytes.extend_from_slice(path);
    }

    #[test]
    fn restore_journal_rejects_duplicate_output_paths() {
        let mut bytes = RESTORE_JOURNAL_MAGIC.to_vec();
        bytes.extend_from_slice(&2u32.to_le_bytes());
        for had_existing in [0, 1] {
            bytes.push(had_existing);
            append_journal_path(&mut bytes, b"dist/value.txt");
        }
        bytes.extend_from_slice(&0u32.to_le_bytes());

        let error = match decode_restore_journal(&bytes) {
            Err(error) => error,
            Ok(_) => panic!("duplicate recovery outputs were accepted"),
        };

        assert!(
            error.to_string().contains("duplicate"),
            "duplicate output diagnostic was unclear: {error}"
        );
    }

    #[test]
    fn restore_journal_rejects_duplicate_directory_paths() {
        let mut bytes = RESTORE_JOURNAL_MAGIC.to_vec();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        append_journal_path(&mut bytes, b"dist/nested");
        append_journal_path(&mut bytes, b"dist/nested");

        let error = match decode_restore_journal(&bytes) {
            Err(error) => error,
            Ok(_) => panic!("duplicate recovery directories were accepted"),
        };

        assert!(
            error.to_string().contains("duplicate"),
            "duplicate directory diagnostic was unclear: {error}"
        );
    }

    #[test]
    fn restore_journal_failure_does_not_publish_a_partial_file() {
        let restore = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let invalid = PathBuf::from(std::ffi::OsString::from("invalid\0path"));

        let error = write_restore_journal(restore.path(), project.path(), &[invalid])
            .expect_err("an invalid path must fail journal publication");

        assert!(
            !restore.path().join(RESTORE_JOURNAL_NAME).exists(),
            "a failed journal write published a partial recovery file: {error}"
        );
    }

    #[test]
    fn restore_journal_writer_rejects_a_directory_count_above_the_decoder_limit() {
        let restore = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let files: Vec<_> = (0..=(MAX_CACHE_ARCHIVE_ENTRIES / 2))
            .map(|index| PathBuf::from(format!("a{index}/b{index}/file")))
            .collect();

        let error = write_restore_journal(restore.path(), project.path(), &files)
            .expect_err("an oversized recovery directory list must be rejected");

        assert!(error.to_string().contains("directory-count cap"));
        assert!(
            !restore.path().join(RESTORE_JOURNAL_NAME).exists(),
            "an oversized recovery journal was published"
        );
    }

    #[test]
    fn staged_restore_publishes_a_trusted_record_before_apply() {
        let root_dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(root_dir.path());
        let project = tempfile::tempdir().unwrap();
        let staged = StagedOutputs::new(&root, project.path()).unwrap();

        assert!(
            staged.registry_record.path.is_file(),
            "staged restore was not registered outside the project"
        );
    }

    #[test]
    fn successful_restore_durably_removes_its_record_and_staging_directory() {
        let root_dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(root_dir.path());
        let project = tempfile::tempdir().unwrap();
        let staged = StagedOutputs::new(&root, project.path()).unwrap();
        let record = staged.registry_record.path.clone();
        let staging = staged.temp_path.clone();

        staged.apply(&[]).unwrap();

        assert!(!record.exists(), "completed restore left a trusted record");
        assert!(!staging.exists(), "completed restore left staging data");
    }
}
