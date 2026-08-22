use crate::added_sources_state::{
    AddedSourceFile, AddedSourceFileAction, AddedSourceRecord, AddedSourcesState,
};
use crate::install_ui;
use lpm_common::LpmError;
use serde::Serialize;
use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn manifest_lookup_keys(package: &str) -> Vec<String> {
    let mut keys = vec![package.to_string()];
    if let Ok(name) = lpm_common::PackageName::parse(package) {
        let scoped = name.scoped();
        if scoped != package {
            keys.push(scoped);
        }
    }
    keys
}

enum FileRemoval {
    Delete,
    Restore {
        backup: PathBuf,
        original_mode: Option<u32>,
    },
}

struct PlannedFileRemoval {
    manifest_path: PathBuf,
    destination: PathBuf,
    operation: FileRemoval,
}

struct MoveEntry {
    source: PathBuf,
    destination: PathBuf,
    #[cfg(unix)]
    source_permissions: Option<std::fs::Permissions>,
}

#[cfg(unix)]
fn regular_file_permissions(path: &Path) -> Result<std::fs::Permissions, LpmError> {
    let metadata = std::fs::symlink_metadata(path).map_err(LpmError::Io)?;
    if !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "refusing source backup that is not a regular file: {}",
            path.display()
        )));
    }
    Ok(metadata.permissions())
}

#[cfg(unix)]
fn apply_recorded_file_permissions(
    path: &Path,
    permissions: std::fs::Permissions,
) -> Result<(), LpmError> {
    let metadata = std::fs::symlink_metadata(path).map_err(LpmError::Io)?;
    if !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "refusing to set the mode of a non-file source backup: {}",
            path.display()
        )));
    }
    std::fs::set_permissions(path, permissions).map_err(LpmError::Io)
}

#[cfg(unix)]
fn apply_recorded_directory_permissions(
    path: &Path,
    permissions: std::fs::Permissions,
) -> Result<(), LpmError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(LpmError::Io)?;
    if !file.metadata().map_err(LpmError::Io)?.is_dir() {
        return Err(LpmError::Registry(format!(
            "refusing to set the mode of a non-directory removal path: {}",
            path.display()
        )));
    }
    file.set_permissions(permissions).map_err(LpmError::Io)
}

#[cfg(not(unix))]
fn apply_recorded_directory_permissions(
    path: &Path,
    permissions: std::fs::Permissions,
) -> Result<(), LpmError> {
    std::fs::set_permissions(path, permissions).map_err(LpmError::Io)
}

struct RemovedDirectory {
    path: PathBuf,
    permissions: std::fs::Permissions,
}

struct RemovalTransaction {
    quarantine: tempfile::TempDir,
    moves: Vec<MoveEntry>,
    removed_directories: Vec<RemovedDirectory>,
    committed: bool,
}

impl RemovalTransaction {
    fn new(project_dir: &Path) -> Result<Self, LpmError> {
        let quarantine = tempfile::Builder::new()
            .prefix(".source-remove-")
            .tempdir_in(project_dir.join(".lpm"))
            .map_err(LpmError::Io)?;
        Ok(Self {
            quarantine,
            moves: Vec::new(),
            removed_directories: Vec::new(),
            committed: false,
        })
    }

    fn move_path(&mut self, source: &Path, destination: &Path) -> Result<(), LpmError> {
        std::fs::rename(source, destination).map_err(LpmError::Io)?;
        self.moves.push(MoveEntry {
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
            #[cfg(unix)]
            source_permissions: None,
        });
        Ok(())
    }

    fn restore_file(
        &mut self,
        source: &Path,
        destination: &Path,
        destination_mode: Option<u32>,
    ) -> Result<(), LpmError> {
        #[cfg(unix)]
        let source_permissions = regular_file_permissions(source)?;
        std::fs::rename(source, destination).map_err(LpmError::Io)?;
        self.moves.push(MoveEntry {
            source: source.to_path_buf(),
            destination: destination.to_path_buf(),
            #[cfg(unix)]
            source_permissions: Some(source_permissions),
        });
        #[cfg(unix)]
        if let Some(mode) = destination_mode {
            use std::os::unix::fs::PermissionsExt as _;

            apply_recorded_file_permissions(destination, std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = destination_mode;
        Ok(())
    }

    fn quarantine_path(&mut self, path: &Path) -> Result<(), LpmError> {
        let destination = self
            .quarantine
            .path()
            .join(format!("entry-{}", self.moves.len()));
        self.move_path(path, &destination)
    }

    fn prune_empty_directories(
        &mut self,
        project_dir: &Path,
        starts: impl IntoIterator<Item = PathBuf>,
    ) -> Result<usize, LpmError> {
        let mut candidates = HashSet::new();
        for start in starts {
            let mut current = start;
            while current.starts_with(project_dir) && current != project_dir {
                candidates.insert(current.clone());
                let Some(parent) = current.parent() else {
                    break;
                };
                current = parent.to_path_buf();
            }
        }
        let mut candidates: Vec<_> = candidates.into_iter().collect();
        candidates.sort_unstable_by(|left, right| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| right.cmp(left))
        });

        for directory in candidates {
            let metadata = match std::fs::symlink_metadata(&directory) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(LpmError::Io(error)),
            };
            let permissions = metadata.permissions();
            match std::fs::remove_dir(&directory) {
                Ok(()) => self.removed_directories.push(RemovedDirectory {
                    path: directory,
                    permissions,
                }),
                Err(error) if matches!(error.kind(), std::io::ErrorKind::DirectoryNotEmpty) => {}
                Err(error) => return Err(LpmError::Io(error)),
            }
        }
        Ok(self.removed_directories.len())
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for RemovalTransaction {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for directory in self.removed_directories.iter().rev() {
            if let Err(error) = std::fs::create_dir_all(&directory.path) {
                tracing::error!(
                    "source removal rollback: failed to recreate {}: {error}",
                    directory.path.display()
                );
                continue;
            }
            if let Err(error) =
                apply_recorded_directory_permissions(&directory.path, directory.permissions.clone())
            {
                tracing::error!(
                    "source removal rollback: failed to restore the mode of {}: {error}",
                    directory.path.display()
                );
            }
        }
        for entry in self.moves.iter().rev() {
            if let Err(error) = std::fs::rename(&entry.destination, &entry.source) {
                tracing::error!(
                    "source removal rollback: failed to restore {}: {error}",
                    entry.source.display()
                );
                continue;
            }
            #[cfg(unix)]
            {
                if let Some(permissions) = &entry.source_permissions
                    && let Err(error) =
                        apply_recorded_file_permissions(&entry.source, permissions.clone())
                {
                    tracing::error!(
                        "source removal rollback: failed to restore the mode of {}: {error}",
                        entry.source.display()
                    );
                }
            }
        }
    }
}

struct SkillRemovalPlan {
    short: String,
    directory: Option<PathBuf>,
    editor_links: Vec<PathBuf>,
}

fn contained_real_directory(
    canonical_project: &Path,
    path: &Path,
    label: &str,
) -> Result<bool, LpmError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(LpmError::Io(error)),
    };
    if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_dir() {
        return Err(LpmError::Registry(format!(
            "refusing {label} that is not a real directory: {}",
            path.display()
        )));
    }
    let canonical = path.canonicalize().map_err(LpmError::Io)?;
    if !canonical.starts_with(canonical_project) {
        return Err(LpmError::Registry(format!(
            "refusing {label} outside the project: {}",
            path.display()
        )));
    }
    Ok(true)
}

fn plan_skill_removal(
    project_dir: &Path,
    canonical_project: &Path,
    package_key: &str,
    recorded_short: Option<&str>,
) -> Result<Option<SkillRemovalPlan>, LpmError> {
    let Some(recorded_short) = recorded_short else {
        return Ok(None);
    };
    let expected_short = package_key
        .strip_prefix("@lpm.dev/")
        .and_then(|_| lpm_common::PackageName::parse(package_key).ok())
        .map(|package| package.short());
    if expected_short.as_deref() != Some(recorded_short) {
        return Err(LpmError::Registry(format!(
            "source state skill identity '{recorded_short}' does not match package '{package_key}'"
        )));
    }

    let skills_root = project_dir.join(".lpm/skills");
    let directory =
        if contained_real_directory(canonical_project, &skills_root, "package skill root")? {
            let directory = skills_root.join(recorded_short);
            contained_real_directory(canonical_project, &directory, "package skill directory")?
                .then_some(directory)
        } else {
            None
        };

    let mut editor_links = Vec::new();
    let cursor_root = project_dir.join(".cursor");
    if contained_real_directory(canonical_project, &cursor_root, "Cursor state directory")? {
        let rules = cursor_root.join("rules");
        if contained_real_directory(canonical_project, &rules, "Cursor rules directory")? {
            let prefix = format!("{recorded_short}--");
            for entry in std::fs::read_dir(&rules).map_err(LpmError::Io)? {
                let entry = entry.map_err(LpmError::Io)?;
                if !entry.file_name().to_string_lossy().starts_with(&prefix) {
                    continue;
                }
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path).map_err(LpmError::Io)?;
                if !metadata.is_file() && !lpm_common::is_symlink_or_junction(&metadata) {
                    return Err(LpmError::Registry(format!(
                        "refusing Cursor package skill entry that is not a file: {}",
                        path.display()
                    )));
                }
                editor_links.push(path);
            }
        }
    }

    Ok(Some(SkillRemovalPlan {
        short: recorded_short.to_string(),
        directory,
        editor_links,
    }))
}

fn validate_file_record(
    project_dir: &Path,
    package_key: &str,
    manifest_path: &Path,
    file: &AddedSourceFile,
) -> Result<Option<PathBuf>, LpmError> {
    match file.action {
        None if file.installed_digest.is_none()
            && file.backup_path.is_none()
            && file.backup_digest.is_none()
            && file.backup_mode.is_none() =>
        {
            Ok(None)
        }
        None => Err(LpmError::Registry(format!(
            "source state for '{}' has incomplete file provenance",
            manifest_path.display()
        ))),
        Some(AddedSourceFileAction::Create) => {
            if file.installed_digest.is_none()
                || file.backup_path.is_some()
                || file.backup_digest.is_some()
                || file.backup_mode.is_some()
            {
                return Err(LpmError::Registry(format!(
                    "source state for '{}' has invalid create provenance",
                    manifest_path.display()
                )));
            }
            Ok(None)
        }
        Some(AddedSourceFileAction::Overwrite) => {
            if file.backup_mode.is_some_and(|mode| mode & !0o7777 != 0) {
                return Err(LpmError::Registry(format!(
                    "source state for '{}' has an invalid backup mode",
                    manifest_path.display()
                )));
            }
            if file.installed_digest.is_none() {
                return Err(LpmError::Registry(format!(
                    "source state for '{}' has no installed integrity",
                    manifest_path.display()
                )));
            }
            let recorded_backup = file.backup_path.as_deref().ok_or_else(|| {
                LpmError::Registry(format!(
                    "source state for '{}' has no overwrite backup",
                    manifest_path.display()
                ))
            })?;
            let relative_backup = crate::added_sources_state::validate_recorded_backup_path(
                package_key,
                manifest_path,
                recorded_backup,
            )?;
            crate::added_sources_state::validate_existing_backup(
                project_dir,
                &relative_backup,
                file.backup_digest.as_deref(),
            )
            .map(Some)
        }
    }
}

fn plan_file_removals(
    project_dir: &Path,
    canonical_project: &Path,
    package_key: &str,
    remaining_state: &AddedSourcesState,
    record: &AddedSourceRecord,
) -> Result<(Vec<PlannedFileRemoval>, AddedSourceRecord, Vec<String>), LpmError> {
    let remaining_file_count = remaining_state
        .packages
        .values()
        .map(|record| record.files.len())
        .sum();
    let mut shared_paths = HashSet::with_capacity(remaining_file_count);
    let mut managed_digests = HashSet::with_capacity(remaining_file_count);
    for record in remaining_state.packages.values() {
        for (path, file) in &record.files {
            shared_paths.insert(path.as_path());
            if let Some(digest) = file.installed_digest.as_deref() {
                managed_digests.insert((path.as_path(), digest));
            }
        }
    }
    let mut removals = Vec::with_capacity(record.files.len());
    let mut retained = AddedSourceRecord::default();
    let mut preserved = Vec::new();

    for (manifest_path, file) in &record.files {
        let destination = crate::added_sources_state::resolve_tracked_manifest_path_from_root(
            canonical_project,
            manifest_path,
        )?;
        let backup = validate_file_record(project_dir, package_key, manifest_path, file)?;
        let exists = match std::fs::symlink_metadata(&destination) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(LpmError::Io(error)),
        };
        let shared = shared_paths.contains(manifest_path.as_path());

        if file.action.is_none() {
            if exists {
                retained.files.insert(manifest_path.clone(), file.clone());
                preserved.push(crate::added_sources_state::display_manifest_path(
                    manifest_path,
                ));
            }
            continue;
        }

        let action = file.action.expect("validated above");
        if shared && action == AddedSourceFileAction::Create {
            if exists {
                preserved.push(crate::added_sources_state::display_manifest_path(
                    manifest_path,
                ));
            }
            continue;
        }

        let installed_digest = file.installed_digest.as_deref().expect("validated above");
        let current_matches =
            exists && crate::added_sources_state::digest_file(&destination)? == installed_digest;
        if exists && !current_matches {
            retained.files.insert(manifest_path.clone(), file.clone());
            preserved.push(crate::added_sources_state::display_manifest_path(
                manifest_path,
            ));
            continue;
        }
        if shared && action == AddedSourceFileAction::Overwrite {
            let backup_digest = file.backup_digest.as_deref().expect("validated above");
            if !current_matches
                || !managed_digests.contains(&(manifest_path.as_path(), backup_digest))
            {
                retained.files.insert(manifest_path.clone(), file.clone());
                if exists {
                    preserved.push(crate::added_sources_state::display_manifest_path(
                        manifest_path,
                    ));
                }
                continue;
            }
        }

        match action {
            AddedSourceFileAction::Create if exists => removals.push(PlannedFileRemoval {
                manifest_path: manifest_path.clone(),
                destination,
                operation: FileRemoval::Delete,
            }),
            AddedSourceFileAction::Create => {}
            AddedSourceFileAction::Overwrite => removals.push(PlannedFileRemoval {
                manifest_path: manifest_path.clone(),
                destination,
                operation: FileRemoval::Restore {
                    backup: backup.expect("validated overwrite backup"),
                    original_mode: file.backup_mode,
                },
            }),
        }
    }

    Ok((removals, retained, preserved))
}

fn plan_dependency_update(
    project_dir: &Path,
    state: &mut AddedSourcesState,
    record: &AddedSourceRecord,
) -> Result<(Option<Vec<u8>>, Vec<String>), LpmError> {
    let mut exclusive = Vec::new();
    for (name, dependency) in &record.dependencies {
        if !dependency.inserted {
            continue;
        }
        let replacement = state
            .packages
            .iter()
            .find_map(|(package, candidate_record)| {
                candidate_record
                    .dependencies
                    .get(name)
                    .filter(|candidate| {
                        candidate.spec == dependency.spec && candidate.section == dependency.section
                    })
                    .map(|_| package.clone())
            });
        if let Some(replacement) = replacement {
            state
                .packages
                .get_mut(&replacement)
                .and_then(|record| record.dependencies.get_mut(name))
                .expect("replacement dependency was found above")
                .inserted = true;
        } else if !state
            .packages
            .values()
            .any(|record| record.dependencies.contains_key(name))
        {
            exclusive.push((name, dependency));
        }
    }
    if exclusive.is_empty() {
        return Ok((None, Vec::new()));
    }

    let manifest_path = project_dir.join("package.json");
    let metadata = match std::fs::symlink_metadata(&manifest_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((None, Vec::new()));
        }
        Err(error) => return Err(LpmError::Io(error)),
    };
    if lpm_common::is_symlink_or_junction(&metadata) || !metadata.is_file() {
        return Err(LpmError::Registry(format!(
            "refusing package manifest that is not a regular file: {}",
            manifest_path.display()
        )));
    }
    let content =
        lpm_common::read_text_file_capped(&manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|error| LpmError::Registry(format!("failed to read package.json: {error}")))?;
    let mut manifest: serde_json::Value = serde_json::from_str(&content)
        .map_err(|error| LpmError::Registry(format!("failed to parse package.json: {error}")))?;
    let object = manifest
        .as_object_mut()
        .ok_or_else(|| LpmError::Registry("package.json root must be a JSON object".to_string()))?;
    let mut removed = Vec::new();
    for (name, dependency) in exclusive {
        let Some(section) = object
            .get_mut(&dependency.section)
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        if section.get(name).and_then(serde_json::Value::as_str) == Some(dependency.spec.as_str()) {
            section.remove(name);
            removed.push(name.clone());
        }
    }
    if removed.is_empty() {
        return Ok((None, removed));
    }
    let mut body = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        LpmError::Registry(format!("failed to serialize package.json: {error}"))
    })?;
    body.push(b'\n');
    Ok((Some(body), removed))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveResult<'a> {
    success: bool,
    package: &'a str,
    removed: &'a [String],
    #[serde(skip_serializing_if = "string_slice_is_empty")]
    preserved: &'a [String],
    #[serde(skip_serializing_if = "string_slice_is_empty")]
    dependencies_removed: &'a [String],
}

fn string_slice_is_empty(values: &&[String]) -> bool {
    values.is_empty()
}

pub async fn run(project_dir: &Path, package: &str, json_output: bool) -> Result<(), LpmError> {
    crate::commands::install::workspace_lockfile::scope_member_project_mutation(
        project_dir,
        run_locked(project_dir, package, json_output),
    )
    .await
}

async fn run_locked(project_dir: &Path, package: &str, json_output: bool) -> Result<(), LpmError> {
    let start = Instant::now();
    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Removing tracked source files for {}",
            install_ui::yellow(package)
        ));
    }

    let (mut state, state_snapshot) =
        crate::added_sources_state::load_state_with_snapshot(project_dir)?;
    let package_key = manifest_lookup_keys(package)
        .into_iter()
        .find(|key| state.package(key).is_some());
    let Some(package_key) = package_key else {
        return render_result(
            start,
            package,
            json_output,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
        );
    };
    let record = state
        .take_package(&package_key)
        .expect("manifest key was found above");
    let canonical_project = project_dir.canonicalize().map_err(LpmError::Io)?;
    let (file_removals, mut retained, preserved) = plan_file_removals(
        project_dir,
        &canonical_project,
        &package_key,
        &state,
        &record,
    )?;
    let skill_plan = plan_skill_removal(
        project_dir,
        &canonical_project,
        &package_key,
        record.skill_package_short.as_deref(),
    )?;
    let (manifest_body, dependencies_removed) =
        plan_dependency_update(project_dir, &mut state, &record)?;
    if !retained.files.is_empty() {
        retained.dependencies.clear();
        retained.skill_package_short = None;
        state.packages.insert(package_key.clone(), retained);
    }

    let state_path = crate::added_sources_state::state_path(project_dir);
    let manifest_path = project_dir.join("package.json");
    let install_hash = project_dir.join(".lpm/install-hash");
    let optional_paths: Vec<&Path> = manifest_body
        .as_ref()
        .map(|_| vec![manifest_path.as_path()])
        .unwrap_or_default();
    let invalidate_paths: Vec<&Path> = manifest_body
        .as_ref()
        .map(|_| vec![install_hash.as_path()])
        .unwrap_or_default();
    let mut manifest_transaction = crate::manifest_tx::ManifestTransaction::snapshot_install_state(
        &[],
        &optional_paths,
        &invalidate_paths,
    )
    .map_err(|error| {
        LpmError::Registry(format!("failed to snapshot source removal state: {error}"))
    })?;
    manifest_transaction
        .snapshot_optional_path_with_bytes(&state_path, state_snapshot)
        .map_err(|error| {
            LpmError::Registry(format!(
                "failed to snapshot added-source state '{}': {error}",
                state_path.display()
            ))
        })?;
    let mut removal_transaction = RemovalTransaction::new(project_dir)?;
    let mut removed = Vec::with_capacity(file_removals.len() + usize::from(skill_plan.is_some()));
    let mut prune_starts = Vec::with_capacity(file_removals.len());

    for planned in file_removals {
        if let Some(parent) = planned.destination.parent() {
            prune_starts.push(parent.to_path_buf());
        }
        match planned.operation {
            FileRemoval::Delete => removal_transaction.quarantine_path(&planned.destination)?,
            FileRemoval::Restore {
                backup,
                original_mode,
            } => {
                if std::fs::symlink_metadata(&planned.destination).is_ok() {
                    removal_transaction.quarantine_path(&planned.destination)?;
                }
                removal_transaction.restore_file(&backup, &planned.destination, original_mode)?;
            }
        }
        removed.push(crate::added_sources_state::display_manifest_path(
            &planned.manifest_path,
        ));
    }

    if let Some(skill_plan) = skill_plan {
        if let Some(directory) = skill_plan.directory {
            removal_transaction.quarantine_path(&directory)?;
            removed.push(format!(".lpm/skills/{}/", skill_plan.short));
        }
        for editor_link in skill_plan.editor_links {
            removal_transaction.quarantine_path(&editor_link)?;
        }
    }
    if let Some(manifest_body) = manifest_body {
        lpm_common::write_file_atomic(&manifest_path, manifest_body).map_err(LpmError::Io)?;
    }
    crate::added_sources_state::write_state(project_dir, &state)?;
    let cleaned_directories =
        removal_transaction.prune_empty_directories(&canonical_project, prune_starts)?;

    manifest_transaction.commit();
    removal_transaction.commit();
    render_result(
        start,
        package,
        json_output,
        removed,
        preserved,
        dependencies_removed,
        cleaned_directories,
    )
}

fn render_result(
    start: Instant,
    package: &str,
    json_output: bool,
    removed: Vec<String>,
    preserved: Vec<String>,
    dependencies_removed: Vec<String>,
    cleaned_directories: usize,
) -> Result<(), LpmError> {
    if json_output {
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer_pretty(
            &mut stdout,
            &RemoveResult {
                success: true,
                package,
                removed: &removed,
                preserved: &preserved,
                dependencies_removed: &dependencies_removed,
            },
        )
        .map_err(|error| {
            LpmError::Registry(format!("failed to serialize remove output: {error}"))
        })?;
        stdout.write_all(b"\n").map_err(LpmError::Io)?;
        return Ok(());
    }

    if removed.is_empty() && preserved.is_empty() && dependencies_removed.is_empty() {
        install_ui::warn_line(crate::install_ui::terminal_line!(
            "No tracked source files found for {}",
            install_ui::yellow(package)
        ));
        return Ok(());
    }
    for path in &removed {
        let path = lpm_common::sanitize_terminal_inline(path);
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {} {}",
            install_ui::red("-"),
            install_ui::dim(&path)
        ));
    }
    for path in &preserved {
        let path = lpm_common::sanitize_terminal_inline(path);
        install_ui::warn_line(crate::install_ui::terminal_line!(
            "Preserved modified or unverified source file {}",
            install_ui::dim(&path)
        ));
    }
    if !dependencies_removed.is_empty() {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Removed {} source-owned dependencies",
            install_ui::green(&dependencies_removed.len().to_string())
        ));
    }
    if cleaned_directories > 0 || removed.iter().any(|path| path.ends_with('/')) {
        install_ui::done("Cleaned empty directories");
    }
    let duration = install_ui::format_duration(start.elapsed());
    install_ui::done_line(crate::install_ui::terminal_line!(
        "Done · removed {} files in {}",
        install_ui::green(&removed.len().to_string()),
        install_ui::green(&duration)
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrite_provenance_rejects_modes_outside_unix_permission_bits() {
        let project = tempfile::tempdir().unwrap();
        let manifest_path = PathBuf::from("Source.ts");
        let source = project.path().join("original.ts");
        std::fs::write(&source, b"original\n").unwrap();
        let backup_path =
            crate::added_sources_state::backup_path_for_file("source-pkg", &manifest_path);
        let backup =
            crate::added_sources_state::write_backup(project.path(), &backup_path, &source)
                .unwrap();
        let file = AddedSourceFile {
            source: Some(PathBuf::from("Source.ts")),
            installed_digest: Some(crate::added_sources_state::digest_bytes(b"installed\n")),
            action: Some(AddedSourceFileAction::Overwrite),
            backup_path: Some(backup_path),
            backup_digest: Some(backup.digest),
            backup_mode: Some(0o10000),
        };

        let error =
            validate_file_record(project.path(), "source-pkg", &manifest_path, &file).unwrap_err();

        assert!(error.to_string().contains("invalid backup mode"));
    }

    #[test]
    fn removal_transaction_drop_restores_an_overwrite_and_its_backup() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let destination = project.path().join("nested/Source.ts");
        std::fs::create_dir(destination.parent().unwrap()).unwrap();
        std::fs::write(&destination, b"installed\n").unwrap();
        let backup = project.path().join(".lpm/backup.bak");
        std::fs::write(&backup, b"original\n").unwrap();
        #[cfg(unix)]
        {
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o640)).unwrap();
            std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        {
            let mut transaction = RemovalTransaction::new(project.path()).unwrap();
            transaction.quarantine_path(&destination).unwrap();
            transaction
                .restore_file(&backup, &destination, Some(0o000))
                .unwrap();
            transaction
                .prune_empty_directories(
                    project.path(),
                    [destination.parent().unwrap().to_path_buf()],
                )
                .unwrap();
        }

        assert_eq!(std::fs::read(&destination).unwrap(), b"installed\n");
        assert_eq!(std::fs::read(&backup).unwrap(), b"original\n");
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o640
            );
            assert_eq!(
                std::fs::metadata(&backup).unwrap().permissions().mode() & 0o7777,
                0o600
            );
        }
    }

    #[test]
    fn removal_transaction_commit_discards_quarantined_content() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let destination = project.path().join("Source.ts");
        std::fs::write(&destination, b"installed\n").unwrap();

        let mut transaction = RemovalTransaction::new(project.path()).unwrap();
        transaction.quarantine_path(&destination).unwrap();
        transaction.commit();

        assert!(!destination.exists());
    }

    #[test]
    fn removal_transaction_drop_recreates_pruned_parent_directories() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        let destination = project.path().join("nested/deep/Source.ts");
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(&destination, b"installed\n").unwrap();
        #[cfg(unix)]
        {
            std::fs::set_permissions(
                project.path().join("nested"),
                std::fs::Permissions::from_mode(0o750),
            )
            .unwrap();
            std::fs::set_permissions(
                project.path().join("nested/deep"),
                std::fs::Permissions::from_mode(0o710),
            )
            .unwrap();
        }

        {
            let mut transaction = RemovalTransaction::new(project.path()).unwrap();
            transaction.quarantine_path(&destination).unwrap();
            transaction
                .prune_empty_directories(
                    project.path(),
                    [destination.parent().unwrap().to_path_buf()],
                )
                .unwrap();
        }

        assert_eq!(std::fs::read(&destination).unwrap(), b"installed\n");
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(project.path().join("nested"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o750
            );
            assert_eq!(
                std::fs::metadata(project.path().join("nested/deep"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o710
            );
        }
    }
}
