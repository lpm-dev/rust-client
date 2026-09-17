use super::plan::{self, SourceContent, StaleFileAction};
use super::target::AddTarget;
use crate::added_sources_state::{self, AddedSourceFile, AddedSourceFileAction, AddedSourcesState};
use lpm_common::LpmError;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Serialize)]
pub(super) struct FileAction {
    pub path: String,
    pub action: &'static str,
}

#[derive(Serialize)]
pub(super) struct PackagePreview {
    pub success: bool,
    pub dry_run: bool,
    pub package: String,
    pub version: String,
    pub target: String,
    pub files: Vec<FileAction>,
    pub dependencies_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stale_files: Vec<FileAction>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies_removed: Vec<plan::RemovedDependency>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_dependencies: Vec<PackagePreview>,
}

#[derive(Default)]
pub(super) struct PreviewState {
    state: Option<AddedSourcesState>,
    manifest: Option<serde_json::Value>,
    paths: BTreeMap<String, Option<String>>,
    directories: HashSet<String>,
    observed_directories: BTreeMap<PathBuf, Vec<std::ffi::OsString>>,
    // Preview leaves version resolution to install, but earlier source declarations protect shared names.
    dependency_owners: HashSet<String>,
    observed: BTreeMap<PathBuf, Option<String>>,
    pub packages: Vec<PackagePreview>,
}

fn digest_if_present(path: &Path) -> Result<Option<String>, LpmError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => added_sources_state::digest_file(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

impl PreviewState {
    pub fn removed(&self, path: &Path) -> bool {
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return false;
        };
        super::project::planned_target_root(parent).is_ok_and(|parent| {
            let path = parent.join(name);
            self.paths
                .get(&super::paths::portable_destination_identity(&path))
                == Some(&None)
        })
    }

    fn prune_directories(
        &mut self,
        project: &Path,
        mut candidates: Vec<PathBuf>,
    ) -> Result<(), LpmError> {
        candidates.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for relative in candidates {
            let directory =
                added_sources_state::resolve_tracked_directory_path_from_root(project, &relative)?;
            let entries = match directory_entries(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            self.observed_directories
                .entry(directory.clone())
                .or_insert_with(|| entries.clone());
            if entries
                .iter()
                .any(|name| !self.removed(&directory.join(name)))
            {
                continue;
            }
            let identity = super::paths::portable_destination_identity(&directory);
            let prefix = format!("{identity}/");
            if self
                .paths
                .range(prefix.clone()..)
                .take_while(|(path, _)| path.starts_with(&prefix))
                .any(|(_, digest)| digest.is_some())
            {
                continue;
            }
            self.paths.insert(identity.clone(), None);
            self.directories.remove(&identity);
        }
        Ok(())
    }

    fn prepare_destination(&mut self, path: &Path) -> Result<(), LpmError> {
        if self
            .directories
            .contains(&super::paths::portable_destination_identity(path))
        {
            return Err(LpmError::Registry(format!(
                "source destination '{}' conflicts with a planned directory",
                path.display()
            )));
        }
        for parent in path.ancestors().skip(1) {
            let identity = super::paths::portable_destination_identity(parent);
            if self.paths.get(&identity).is_some_and(Option::is_some) {
                return Err(LpmError::Registry(format!(
                    "source destination '{}' requires a directory at planned file '{}'",
                    path.display(),
                    parent.display()
                )));
            }
            self.directories.insert(identity);
        }
        Ok(())
    }

    fn current(&mut self, path: &Path) -> Result<Option<String>, LpmError> {
        let identity = super::paths::portable_destination_identity(path);
        if let Some(digest) = self.paths.get(&identity) {
            return Ok(digest.clone());
        }
        let digest = digest_if_present(path)?;
        self.observed
            .entry(path.to_path_buf())
            .or_insert_with(|| digest.clone());
        Ok(digest)
    }

    fn set(&mut self, path: &Path, digest: Option<String>) {
        self.paths
            .insert(super::paths::portable_destination_identity(path), digest);
    }

    fn manifest(&mut self, project: &Path) -> Result<&mut serde_json::Value, LpmError> {
        if self.manifest.is_none() {
            let path = project.join("package.json");
            let content =
                lpm_common::read_text_file_capped(&path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)?;
            self.observed.insert(
                path,
                Some(added_sources_state::digest_bytes(content.as_bytes())),
            );
            self.manifest = Some(serde_json::from_str(&content).map_err(|error| {
                LpmError::Registry(format!("failed to parse package.json: {error}"))
            })?);
        }
        self.manifest
            .as_mut()
            .ok_or_else(|| LpmError::Registry("source preview requires package.json".into()))
    }

    pub fn ensure_unchanged(&self) -> Result<(), LpmError> {
        for (path, expected) in &self.observed_directories {
            if &directory_entries(path)? != expected {
                return Err(LpmError::Registry(format!(
                    "project directory changed during source preview: {}. Run the preview again",
                    path.display()
                )));
            }
        }
        for (path, expected) in &self.observed {
            if &digest_if_present(path)? != expected {
                return Err(LpmError::Registry(format!(
                    "project file changed during source preview: {}. Run the preview again",
                    path.display()
                )));
            }
        }
        Ok(())
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "source preview uses the same resolved package and copy context as delivery"
)]
pub(super) fn plan_package(
    project: &Path,
    sources: &Path,
    target: &Path,
    files: &[(String, String)],
    destinations: &[PathBuf],
    content: &SourceContent<'_>,
    force: bool,
    package: &AddTarget,
    version: &str,
    no_install_deps: bool,
    dependencies: &[(String, crate::save_spec::UserSaveIntent)],
    preview: &mut PreviewState,
) -> Result<(), LpmError> {
    let mut state = match preview.state.take() {
        Some(state) => state,
        None => {
            let (state, snapshot) = added_sources_state::load_state_with_snapshot(project)?;
            preview.observed.insert(
                added_sources_state::state_path(project),
                snapshot.as_deref().map(added_sources_state::digest_bytes),
            );
            state
        }
    };
    let key = package.json_name();
    let previous = state.take_package(&key);
    let mut tracked_files = Vec::with_capacity(files.len());
    let mut actions = Vec::with_capacity(files.len());
    let mut declared = HashSet::with_capacity(files.len());
    let mut external_imports = HashSet::new();
    for ((source_relative, destination_relative), destination) in files.iter().zip(destinations) {
        let source = sources.join(source_relative);
        preview.prepare_destination(destination)?;
        let manifest_path = added_sources_state::manifest_path_for_file(project, destination);
        declared.insert(manifest_path.clone());
        let previous_file = previous
            .as_ref()
            .and_then(|record| record.files.get(&manifest_path));
        let current = preview.current(destination)?;
        let prepared = content.prepare(
            &source,
            source_relative,
            destination_relative,
            &mut external_imports,
        )?;
        let incoming = match &prepared {
            Some(text) => added_sources_state::digest_bytes(text.as_bytes()),
            None => added_sources_state::digest_file(&source)?,
        };
        let managed = plan::managed_file_matches(previous_file, current.as_deref());
        let action = if current.is_none() {
            "create"
        } else if managed && current.as_ref() == Some(&incoming) {
            "skip"
        } else if managed || force {
            "overwrite"
        } else {
            "skip"
        };
        if action == "skip" {
            if let Some(previous_file) = previous_file {
                if managed {
                    super::validate_previous_file_provenance(
                        project,
                        &key,
                        &manifest_path,
                        previous_file,
                    )?;
                }
                tracked_files.push((manifest_path, previous_file.clone()));
            }
        } else {
            let file =
                if let Some(previous_file) = previous_file.filter(|file| file.action.is_some()) {
                    super::validate_previous_file_provenance(
                        project,
                        &key,
                        &manifest_path,
                        previous_file,
                    )?;
                    AddedSourceFile {
                        source: Some(PathBuf::from(source_relative)),
                        installed_digest: Some(incoming.clone()),
                        ..previous_file.clone()
                    }
                } else {
                    let backup_path = current
                        .as_ref()
                        .map(|_| added_sources_state::backup_path_for_file(&key, &manifest_path));
                    if let Some(backup) = &backup_path {
                        preview.set(&project.join(backup), current.clone());
                    }
                    AddedSourceFile {
                        source: Some(PathBuf::from(source_relative)),
                        installed_digest: Some(incoming.clone()),
                        action: Some(if current.is_some() {
                            AddedSourceFileAction::Overwrite
                        } else {
                            AddedSourceFileAction::Create
                        }),
                        backup_path,
                        backup_digest: current.clone(),
                        backup_mode: None,
                    }
                };
            preview.set(destination, Some(incoming));
            tracked_files.push((manifest_path, file));
        }
        actions.push(FileAction {
            path: destination_relative.clone(),
            action,
        });
    }
    let shared = state
        .packages
        .values()
        .flat_map(|record| record.files.keys())
        .collect::<HashSet<_>>();
    let mut stale_files = Vec::new();
    let mut reconciled = Vec::new();
    if let Some(previous) = &previous {
        for (path, file) in &previous.files {
            if declared.contains(path) {
                continue;
            }
            if shared.contains(path) {
                tracked_files.push((path.clone(), file.clone()));
                stale_files.push(FileAction {
                    path: path.to_string_lossy().replace('\\', "/"),
                    action: "preserve",
                });
                continue;
            }
            let destination = added_sources_state::resolve_tracked_manifest_path(project, path)?;
            if file.installed_digest.is_none() {
                tracked_files.push((path.clone(), file.clone()));
                stale_files.push(FileAction {
                    path: path.to_string_lossy().replace('\\', "/"),
                    action: "preserve",
                });
                continue;
            }
            let current = preview.current(&destination)?;
            let action = plan::stale_file_action(shared.contains(path), file, current.as_deref());
            match action {
                StaleFileAction::Preserve => tracked_files.push((path.clone(), file.clone())),
                StaleFileAction::Remove | StaleFileAction::Forget => {
                    reconciled.push(path.clone());
                    preview.set(&destination, None)
                }
                StaleFileAction::Restore => {
                    reconciled.push(path.clone());
                    let (_, backup, digest, _) =
                        super::validate_previous_file_provenance(project, &key, path, file)?;
                    if let Some(backup) = backup {
                        let backup = project.join(backup);
                        preview.current(&backup)?;
                        preview.set(&backup, None);
                    }
                    preview.set(&destination, digest);
                }
            }
            stale_files.push(FileAction {
                path: path.to_string_lossy().replace('\\', "/"),
                action: action.as_str(),
            });
        }
    }
    let retained_ancestors = added_sources_state::tracked_file_ancestor_directories(
        tracked_files.iter().map(|(path, _)| path.as_path()),
    );
    let reconciled_ancestors = added_sources_state::tracked_file_ancestor_directories(
        reconciled.iter().map(PathBuf::as_path),
    );
    let other_ancestors = added_sources_state::tracked_file_ancestor_directories(
        state
            .packages
            .values()
            .flat_map(|record| record.files.keys().map(PathBuf::as_path)),
    );
    if let Some(previous) = &previous {
        preview.prune_directories(
            project,
            previous
                .created_directories
                .iter()
                .filter(|path| {
                    !retained_ancestors.contains(*path)
                        && !other_ancestors.contains(*path)
                        && reconciled_ancestors.contains(*path)
                })
                .cloned()
                .collect(),
        )?;
    }
    let desired = dependencies
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<HashSet<_>>();
    let mut candidates = if no_install_deps {
        Vec::new()
    } else {
        plan::stale_dependency_candidates(&mut state, previous.as_ref(), &desired)
    };
    candidates.retain(|(name, _)| !preview.dependency_owners.contains(name));
    let removed = if candidates.is_empty() {
        Vec::new()
    } else {
        plan::remove_unchanged_dependencies(preview.manifest(project)?, &candidates)?
    };
    let tracked_dependencies = previous.as_ref().map(|record| {
        record
            .dependencies
            .iter()
            .filter(|(name, _)| no_install_deps || desired.contains(name.as_str()))
            .map(|(name, dependency)| (name.clone(), dependency.clone()))
            .collect()
    });
    if !no_install_deps {
        preview
            .dependency_owners
            .extend(desired.into_iter().map(str::to_string));
    }
    state.record_package_delivery(
        &key,
        tracked_files,
        std::iter::empty(),
        tracked_dependencies,
        previous
            .as_ref()
            .and_then(|record| record.skill_package_short.as_deref()),
    );
    preview.state = Some(state);
    preview.packages.push(PackagePreview {
        success: true,
        dry_run: true,
        package: key,
        version: version.to_string(),
        target: target
            .strip_prefix(project)
            .unwrap_or(target)
            .to_string_lossy()
            .replace('\\', "/"),
        files: actions,
        dependencies_count: if no_install_deps || !content.configured {
            0
        } else {
            dependencies.len()
        },
        stale_files,
        dependencies_removed: removed,
        source_dependencies: Vec::new(),
    });
    Ok(())
}

fn directory_entries(path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || lpm_common::is_symlink_or_junction(&metadata) {
        return Err(std::io::Error::other(
            "source preview directory is linked or not a directory",
        ));
    }
    let mut entries = std::fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_unstable();
    Ok(entries)
}
