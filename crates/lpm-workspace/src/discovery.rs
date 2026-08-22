use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::error::WorkspaceError;
use crate::package_json::{LpmConfig, PackageJson, WorkspacesConfig, read_package_json};

#[derive(Debug, Clone)]
pub struct Workspace {
    /// Path to the workspace root (where the root package.json lives).
    pub root: PathBuf,
    /// Root package.json data.
    pub root_package: PackageJson,
    /// Discovered member packages.
    pub members: Vec<WorkspaceMember>,
}

/// A single workspace member package.
#[derive(Debug, Clone)]
pub struct WorkspaceMember {
    /// Path to the member's directory.
    pub path: PathBuf,
    /// Parsed package.json.
    pub package: PackageJson,
}

#[derive(Deserialize)]
struct WorkspacePackageName {
    name: Option<String>,
}

struct WorkspaceMemberScan {
    member_paths: Vec<PathBuf>,
    directory_paths: Vec<PathBuf>,
}

struct WorkspaceGenerationEntry {
    relative_path: PathBuf,
    directory: bool,
    metadata: WorkspaceMetadataGeneration,
}

#[derive(PartialEq, Eq)]
struct WorkspaceMetadataGeneration {
    len: u64,
    modified: cap_std::time::SystemTime,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    attributes: u32,
}

/// An opaque filesystem generation captured for release-publish revalidation.
pub struct PublishWorkspaceGeneration {
    root_package: PackageJson,
    inclusions: Vec<WorkspaceGlob>,
    exclusions: Vec<WorkspaceGlob>,
    entries: Vec<WorkspaceGenerationEntry>,
}

/// Cached workspace state used to construct one release-publish projection.
pub struct PublishProjectionContext<'a> {
    member_paths_by_name: &'a HashMap<String, PathBuf>,
    member_paths: &'a [PathBuf],
    generation: &'a PublishWorkspaceGeneration,
    validate_generation: bool,
}

impl<'a> PublishProjectionContext<'a> {
    pub fn new(
        member_paths_by_name: &'a HashMap<String, PathBuf>,
        member_paths: &'a [PathBuf],
        generation: &'a PublishWorkspaceGeneration,
        validate_generation: bool,
    ) -> Self {
        Self {
            member_paths_by_name,
            member_paths,
            generation,
            validate_generation,
        }
    }
}

pub struct OpenWorkspaceRoot {
    path: PathBuf,
    directory: cap_std::fs::Dir,
}

impl OpenWorkspaceRoot {
    #[inline]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[inline]
    pub fn directory(&self) -> &cap_std::fs::Dir {
        &self.directory
    }

    pub fn into_parts(self) -> (PathBuf, cap_std::fs::Dir) {
        (self.path, self.directory)
    }
}

pub fn discover_workspace(start_dir: &Path) -> Result<Option<Workspace>, WorkspaceError> {
    let original_start = start_dir.to_path_buf();
    let mut current = start_dir.to_path_buf();

    loop {
        match read_workspace_root(&current) {
            Ok((root_package, pnpm_workspace)) => {
                let globs = workspace_member_globs(&root_package, pnpm_workspace.as_ref());
                if !globs.is_empty() {
                    let members = discover_members(&current, &globs)?;
                    validate_unique_package_names(&current, &root_package, &members)?;
                    warn_on_member_catalogs(&members);
                    let workspace = Workspace {
                        root: current.clone(),
                        root_package,
                        members,
                    };

                    let start_is_root = original_start == workspace.root;
                    let start_within_root = original_start.starts_with(&workspace.root);
                    let start_is_member = workspace
                        .members
                        .iter()
                        .any(|member| original_start.starts_with(&member.path));
                    let has_nested_non_member_package = start_within_root
                        && has_intermediate_non_member_package_json(
                            &original_start,
                            &workspace.root,
                            &workspace.members,
                        );

                    if start_is_root
                        || start_is_member
                        || (start_within_root && !has_nested_non_member_package)
                    {
                        return Ok(Some(workspace));
                    }
                }
            }
            Err(WorkspaceError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }

        // Walk up to parent
        if !current.pop() {
            break;
        }
    }

    Ok(None)
}

/// Discover one already-selected workspace without reopening its root by name.
pub fn discover_workspace_from_open_root(
    root_path: &Path,
    root_dir: &cap_std::fs::Dir,
    start_dir: &Path,
) -> Result<Option<Workspace>, WorkspaceError> {
    let (root_package, pnpm_workspace) = read_workspace_root_from_open_dir(root_path, root_dir)?;
    let globs = workspace_member_globs(&root_package, pnpm_workspace.as_ref());
    if globs.is_empty() {
        return Ok(None);
    }
    let members = discover_members_from_open_root(root_path, root_dir, &globs)?;
    validate_unique_package_names(root_path, &root_package, &members)?;
    warn_on_member_catalogs(&members);
    let workspace = Workspace {
        root: root_path.to_path_buf(),
        root_package,
        members,
    };
    let start_is_root = start_dir == root_path;
    let start_is_member = workspace
        .members
        .iter()
        .any(|member| start_dir.starts_with(&member.path));
    if start_is_root || start_is_member {
        Ok(Some(workspace))
    } else {
        Ok(None)
    }
}

pub fn read_publish_projection_from_open_root(
    root_path: &Path,
    root_dir: &cap_std::fs::Dir,
    project_path: &Path,
    project_package_json: &str,
    context: &PublishProjectionContext<'_>,
) -> Result<Workspace, WorkspaceError> {
    let refreshed_root;
    let refreshed_globs;
    let (root_package, inclusions, exclusions) =
        if !context.validate_generation || context.generation.is_current(root_dir)? {
            (
                &context.generation.root_package,
                context.generation.inclusions.as_slice(),
                context.generation.exclusions.as_slice(),
            )
        } else {
            let (root_package, pnpm_workspace) =
                read_workspace_root_from_open_dir(root_path, root_dir)?;
            let globs = workspace_member_globs(&root_package, pnpm_workspace.as_ref());
            refreshed_root = root_package;
            refreshed_globs = compile_workspace_globs(root_path, &globs)?;
            let current_member_scan = discover_member_paths_from_open_root(
                root_path,
                root_dir,
                &refreshed_globs.0,
                &refreshed_globs.1,
            )?;
            validate_publish_workspace_names_from_open_root(
                root_path,
                root_dir,
                &refreshed_root,
                &current_member_scan.member_paths,
                Some((project_path, project_package_json)),
                context.member_paths_by_name,
                context.member_paths,
            )?;
            (
                &refreshed_root,
                refreshed_globs.0.as_slice(),
                refreshed_globs.1.as_slice(),
            )
        };
    if inclusions.is_empty()
        || !compiled_workspace_globs_include_project(
            project_path,
            root_path,
            inclusions,
            exclusions,
        )?
    {
        return Err(WorkspaceError::Parse(format!(
            "workspace member {} is no longer selected by {}",
            project_path.display(),
            root_path.display()
        )));
    }
    let project_package =
        serde_json::from_str::<PackageJson>(lpm_common::strip_utf8_bom_str(project_package_json))
            .map_err(|error| {
            WorkspaceError::Parse(format!(
                "failed to parse {}: {error}",
                project_path.join("package.json").display()
            ))
        })?;
    let dependency_sections = [
        &project_package.dependencies,
        &project_package.dev_dependencies,
        &project_package.peer_dependencies,
        &project_package.optional_dependencies,
    ];
    let referenced_names = dependency_sections
        .into_iter()
        .flat_map(|dependencies| dependencies.iter())
        .filter_map(|(name, _)| {
            context
                .member_paths_by_name
                .contains_key(name)
                .then_some(name)
        });
    let mut seen_paths = HashSet::with_capacity(context.member_paths_by_name.len().min(8));
    seen_paths.insert(project_path);
    let mut members = Vec::with_capacity(1 + referenced_names.size_hint().0);
    for name in referenced_names {
        let Some(member_path) = context.member_paths_by_name.get(name) else {
            continue;
        };
        if !seen_paths.insert(member_path.as_path()) {
            continue;
        }
        if !compiled_workspace_globs_include_project(
            member_path,
            root_path,
            inclusions,
            exclusions,
        )? {
            return Err(WorkspaceError::Parse(format!(
                "workspace dependency {} is no longer selected by {}",
                member_path.display(),
                root_path.display()
            )));
        }
        let relative = member_path.strip_prefix(root_path).map_err(|_| {
            WorkspaceError::Parse(format!(
                "workspace dependency {} is outside {}",
                member_path.display(),
                root_path.display()
            ))
        })?;
        let directory = open_relative_directory(root_dir, relative)?.ok_or_else(|| {
            WorkspaceError::NotFound(member_path.join("package.json").display().to_string())
        })?;
        let package = read_package_json_from_open_dir(
            &directory,
            Path::new("package.json"),
            &member_path.join("package.json"),
        )?;
        members.push(WorkspaceMember {
            path: member_path.clone(),
            package,
        });
    }
    members.push(WorkspaceMember {
        path: project_path.to_path_buf(),
        package: project_package,
    });

    Ok(Workspace {
        root: root_path.to_path_buf(),
        root_package: root_package.clone(),
        members,
    })
}

/// Capture the workspace member and configuration generation used by release publishing.
pub fn capture_publish_workspace_generation_from_open_root(
    root_path: &Path,
    root_dir: &cap_std::fs::Dir,
    expected_paths_by_name: &HashMap<String, PathBuf>,
    expected_member_paths: &[PathBuf],
) -> Result<PublishWorkspaceGeneration, WorkspaceError> {
    let (root_package, pnpm_workspace) = read_workspace_root_from_open_dir(root_path, root_dir)?;
    let globs = workspace_member_globs(&root_package, pnpm_workspace.as_ref());
    let (inclusions, exclusions) = compile_workspace_globs(root_path, &globs)?;
    let member_scan =
        discover_member_paths_from_open_root(root_path, root_dir, &inclusions, &exclusions)?;
    validate_publish_workspace_names_from_open_root(
        root_path,
        root_dir,
        &root_package,
        &member_scan.member_paths,
        None,
        expected_paths_by_name,
        expected_member_paths,
    )?;

    let mut directory_paths = member_scan.directory_paths;
    directory_paths.push(PathBuf::new());
    directory_paths.sort_unstable();
    directory_paths.dedup();
    let mut entries =
        Vec::with_capacity(directory_paths.len() + member_scan.member_paths.len() + 2);
    for relative_path in directory_paths {
        entries.push(capture_workspace_generation_entry(
            root_dir,
            relative_path,
            true,
        )?);
    }
    entries.push(capture_workspace_generation_entry(
        root_dir,
        PathBuf::from("package.json"),
        false,
    )?);
    if root_dir.symlink_metadata("pnpm-workspace.yaml").is_ok() {
        entries.push(capture_workspace_generation_entry(
            root_dir,
            PathBuf::from("pnpm-workspace.yaml"),
            false,
        )?);
    }
    for relative_path in member_scan.member_paths {
        entries.push(capture_workspace_generation_entry(
            root_dir,
            relative_path.join("package.json"),
            false,
        )?);
    }
    Ok(PublishWorkspaceGeneration {
        root_package,
        inclusions,
        exclusions,
        entries,
    })
}

impl PublishWorkspaceGeneration {
    fn is_current(&self, root_dir: &cap_std::fs::Dir) -> Result<bool, WorkspaceError> {
        for expected in &self.entries {
            let Some(metadata) = workspace_generation_metadata(root_dir, &expected.relative_path)?
            else {
                return Ok(false);
            };
            if metadata.is_dir() != expected.directory
                || metadata_is_link_or_reparse(&metadata)
                || workspace_metadata_generation(&metadata, &expected.relative_path)?
                    != expected.metadata
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn capture_workspace_generation_entry(
    root_dir: &cap_std::fs::Dir,
    relative_path: PathBuf,
    directory: bool,
) -> Result<WorkspaceGenerationEntry, WorkspaceError> {
    let metadata = workspace_generation_metadata(root_dir, &relative_path)?
        .ok_or_else(|| WorkspaceError::NotFound(relative_path.display().to_string()))?;
    if metadata.is_dir() != directory || metadata_is_link_or_reparse(&metadata) {
        return Err(WorkspaceError::Io(format!(
            "workspace generation path {} changed type",
            relative_path.display()
        )));
    }
    let generation = workspace_metadata_generation(&metadata, &relative_path)?;
    Ok(WorkspaceGenerationEntry {
        relative_path,
        directory,
        metadata: generation,
    })
}

fn workspace_generation_metadata(
    root_dir: &cap_std::fs::Dir,
    relative_path: &Path,
) -> Result<Option<cap_std::fs::Metadata>, WorkspaceError> {
    let result = if relative_path.as_os_str().is_empty() {
        root_dir.dir_metadata()
    } else {
        root_dir.symlink_metadata(relative_path)
    };
    match result {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(WorkspaceError::Io(format!(
            "failed to inspect workspace generation path {}: {error}",
            relative_path.display()
        ))),
    }
}

fn workspace_metadata_generation(
    metadata: &cap_std::fs::Metadata,
    relative_path: &Path,
) -> Result<WorkspaceMetadataGeneration, WorkspaceError> {
    let modified = metadata.modified().map_err(|error| {
        WorkspaceError::Io(format!(
            "failed to inspect workspace generation for {}: {error}",
            relative_path.display()
        ))
    })?;
    #[cfg(unix)]
    use cap_std::fs::MetadataExt as _;
    #[cfg(windows)]
    use cap_std::fs::MetadataExt as _;
    Ok(WorkspaceMetadataGeneration {
        len: metadata.len(),
        modified,
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        changed_seconds: metadata.ctime(),
        #[cfg(unix)]
        changed_nanoseconds: metadata.ctime_nsec(),
        #[cfg(windows)]
        creation_time: metadata.creation_time(),
        #[cfg(windows)]
        attributes: metadata.file_attributes(),
    })
}

/// Find the applicable workspace root without reading or retaining member manifests.
pub fn find_workspace_root(start_dir: &Path) -> Result<Option<PathBuf>, WorkspaceError> {
    let mut current = start_dir.to_path_buf();

    loop {
        match read_workspace_root(&current) {
            Ok((root_package, pnpm_workspace)) => {
                let globs = workspace_member_globs(&root_package, pnpm_workspace.as_ref());
                if !globs.is_empty() && start_belongs_to_workspace(start_dir, &current, &globs)? {
                    return Ok(Some(current));
                }
            }
            Err(WorkspaceError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        if !current.pop() {
            return Ok(None);
        }
    }
}

pub fn find_workspace_root_from_open_project(
    start_path: &Path,
    start_dir: &cap_std::fs::Dir,
) -> Result<Option<OpenWorkspaceRoot>, WorkspaceError> {
    let start_identity = open_directory_identity(start_dir, start_path)?;
    let mut current = start_path.to_path_buf();
    loop {
        let directory = if current == start_path {
            start_dir.try_clone().map_err(|error| {
                WorkspaceError::Io(format!(
                    "failed to retain workspace candidate {}: {error}",
                    current.display()
                ))
            })?
        } else {
            open_directory_nofollow(&current).map_err(|error| {
                WorkspaceError::Io(format!(
                    "failed to open workspace candidate {} safely: {error}",
                    current.display()
                ))
            })?
        };
        match read_workspace_root_from_open_dir(&current, &directory) {
            Ok((root_package, pnpm_workspace)) => {
                let globs = workspace_member_globs(&root_package, pnpm_workspace.as_ref());
                if !globs.is_empty()
                    && (current == start_path
                        || workspace_globs_include_project(start_path, &current, &globs)?)
                {
                    let relative_project = start_path.strip_prefix(&current).map_err(|_| {
                        WorkspaceError::Parse(format!(
                            "selected project {} is outside workspace candidate {}",
                            start_path.display(),
                            current.display()
                        ))
                    })?;
                    let Some(project_from_candidate) =
                        open_relative_directory(&directory, relative_project)?
                    else {
                        return Err(WorkspaceError::Io(format!(
                            "selected project {} changed while choosing workspace root {}",
                            start_path.display(),
                            current.display()
                        )));
                    };
                    if open_directory_identity(&project_from_candidate, start_path)?
                        != start_identity
                    {
                        return Err(WorkspaceError::Io(format!(
                            "selected project {} does not belong to workspace root generation {}",
                            start_path.display(),
                            current.display()
                        )));
                    }
                    return Ok(Some(OpenWorkspaceRoot {
                        path: current,
                        directory,
                    }));
                }
            }
            Err(WorkspaceError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        if !current.pop() {
            return Ok(None);
        }
    }
}

fn open_directory_identity(
    directory: &cap_std::fs::Dir,
    display: &Path,
) -> Result<same_file::Handle, WorkspaceError> {
    let file = directory.try_clone().map_err(|error| {
        WorkspaceError::Io(format!(
            "failed to retain directory identity for {}: {error}",
            display.display()
        ))
    })?;
    same_file::Handle::from_file(file.into_std_file()).map_err(|error| {
        WorkspaceError::Io(format!(
            "failed to identify directory {}: {error}",
            display.display()
        ))
    })
}

fn workspace_globs_include_project(
    project: &Path,
    root: &Path,
    globs: &[String],
) -> Result<bool, WorkspaceError> {
    let (inclusions, exclusions) = compile_workspace_globs(root, globs)?;
    compiled_workspace_globs_include_project(project, root, &inclusions, &exclusions)
}

fn compile_workspace_globs(
    root: &Path,
    globs: &[String],
) -> Result<(Vec<WorkspaceGlob>, Vec<WorkspaceGlob>), WorkspaceError> {
    let mut inclusions = Vec::with_capacity(globs.len());
    let mut exclusions = Vec::new();
    for raw in globs {
        if let Some(excluded) = raw.strip_prefix('!') {
            exclusions.push(WorkspaceGlob::compile(root, excluded)?);
        } else {
            inclusions.push(WorkspaceGlob::compile(root, raw)?);
        }
    }
    Ok((inclusions, exclusions))
}

fn compiled_workspace_globs_include_project(
    project: &Path,
    root: &Path,
    inclusions: &[WorkspaceGlob],
    exclusions: &[WorkspaceGlob],
) -> Result<bool, WorkspaceError> {
    let relative = project.strip_prefix(root).map_err(|_| {
        WorkspaceError::Parse(format!(
            "workspace candidate {} is outside {}",
            project.display(),
            root.display()
        ))
    })?;
    Ok(inclusions
        .iter()
        .any(|glob| glob.matches_relative_directory(relative))
        && !exclusions
            .iter()
            .any(|glob| glob.matches_relative_directory(relative)))
}

fn start_belongs_to_workspace(
    start: &Path,
    root: &Path,
    globs: &[String],
) -> Result<bool, WorkspaceError> {
    if start == root {
        return Ok(true);
    }
    let mut current = Some(start);
    while let Some(directory) = current {
        if directory == root {
            return Ok(true);
        }
        if directory.join("package.json").is_file() {
            let relative = directory.strip_prefix(root).map_err(|_| {
                WorkspaceError::Parse(format!(
                    "workspace candidate {} is outside {}",
                    directory.display(),
                    root.display()
                ))
            })?;
            let mut included = false;
            let mut excluded = false;
            for raw in globs {
                if let Some(raw) = raw.strip_prefix('!') {
                    excluded |=
                        WorkspaceGlob::compile(root, raw)?.matches_relative_directory(relative);
                } else {
                    included |=
                        WorkspaceGlob::compile(root, raw)?.matches_relative_directory(relative);
                }
            }
            return Ok(included && !excluded);
        }
        current = directory.parent();
    }
    Ok(false)
}

fn validate_unique_package_names(
    root: &Path,
    root_package: &PackageJson,
    members: &[WorkspaceMember],
) -> Result<(), WorkspaceError> {
    let mut paths_by_name = std::collections::BTreeMap::<&str, Vec<&Path>>::new();
    if let Some(name) = root_package.name.as_deref() {
        paths_by_name.entry(name).or_default().push(root);
    }
    for member in members {
        if let Some(name) = member.package.name.as_deref() {
            paths_by_name.entry(name).or_default().push(&member.path);
        }
    }
    let conflicts = paths_by_name
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(name, mut paths)| {
            paths.sort_unstable();
            let paths = paths
                .into_iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{name:?}: {paths}")
        })
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        return Ok(());
    }
    Err(WorkspaceError::Parse(format!(
        "duplicate workspace package names are not allowed: {}",
        conflicts.join("; ")
    )))
}

fn validate_publish_workspace_names_from_open_root(
    root_path: &Path,
    root_dir: &cap_std::fs::Dir,
    root_package: &PackageJson,
    current_member_paths: &[PathBuf],
    current_project: Option<(&Path, &str)>,
    expected_paths_by_name: &HashMap<String, PathBuf>,
    expected_member_paths: &[PathBuf],
) -> Result<(), WorkspaceError> {
    let expected_relative_paths = expected_member_paths
        .iter()
        .map(|path| {
            path.strip_prefix(root_path)
                .map(Path::to_path_buf)
                .map_err(|_| {
                    WorkspaceError::Parse(format!(
                        "workspace member {} is outside {}",
                        path.display(),
                        root_path.display()
                    ))
                })
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let current_relative_paths = current_member_paths
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if current_relative_paths != expected_relative_paths {
        return Err(WorkspaceError::Parse(
            "workspace member set changed after release publish preflight; retry the command"
                .into(),
        ));
    }

    let mut expected_names_by_path = HashMap::with_capacity(expected_paths_by_name.len());
    for (name, path) in expected_paths_by_name {
        expected_names_by_path.insert(path.as_path(), name.as_str());
    }
    let mut paths_by_name = std::collections::BTreeMap::<String, Vec<PathBuf>>::new();
    if let Some(name) = root_package.name.as_ref() {
        paths_by_name
            .entry(name.clone())
            .or_default()
            .push(root_path.to_path_buf());
    }
    let mut renamed_member = None;
    for relative in current_member_paths {
        let path = root_path.join(relative);
        let name = if let Some((_, project_package_json)) =
            current_project.filter(|(project_path, _)| path == *project_path)
        {
            serde_json::from_str::<WorkspacePackageName>(lpm_common::strip_utf8_bom_str(
                project_package_json,
            ))
            .map(|package| package.name)
            .map_err(|error| {
                WorkspaceError::Parse(format!(
                    "failed to parse {}: {error}",
                    path.join("package.json").display()
                ))
            })?
        } else {
            let directory = open_relative_directory(root_dir, relative)?.ok_or_else(|| {
                WorkspaceError::NotFound(path.join("package.json").display().to_string())
            })?;
            read_workspace_package_name_from_open_dir(&directory, &path.join("package.json"))?
        };
        let expected_name = expected_names_by_path.get(path.as_path()).copied();
        if name.as_deref() != expected_name && renamed_member.is_none() {
            renamed_member = Some(path.clone());
        }
        if let Some(name) = name {
            paths_by_name.entry(name).or_default().push(path);
        }
    }
    let conflicts = paths_by_name
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(name, mut paths)| {
            paths.sort_unstable();
            let paths = paths
                .into_iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!("{name:?}: {paths}")
        })
        .collect::<Vec<_>>();
    if conflicts.is_empty() {
        if let Some(path) = renamed_member {
            return Err(WorkspaceError::Parse(format!(
                "workspace package name changed for {}; retry the command",
                path.display()
            )));
        }
        return Ok(());
    }
    Err(WorkspaceError::Parse(format!(
        "duplicate workspace package names are not allowed: {}",
        conflicts.join("; ")
    )))
}

fn read_workspace_package_name_from_open_dir(
    directory: &cap_std::fs::Dir,
    display_path: &Path,
) -> Result<Option<String>, WorkspaceError> {
    let content = read_text_from_open_dir(
        directory,
        Path::new("package.json"),
        display_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        false,
    )?
    .ok_or_else(|| WorkspaceError::NotFound(display_path.display().to_string()))?;
    serde_json::from_str::<WorkspacePackageName>(lpm_common::strip_utf8_bom_str(&content))
        .map(|package| package.name)
        .map_err(|error| {
            WorkspaceError::Parse(format!(
                "failed to parse {}: {error}",
                display_path.display()
            ))
        })
}

fn workspace_member_globs(
    root_package: &PackageJson,
    pnpm_workspace: Option<&PnpmWorkspaceConfig>,
) -> Vec<String> {
    let package_json_globs: &[String] = match &root_package.workspaces {
        Some(WorkspacesConfig::Globs(globs)) => globs,
        Some(WorkspacesConfig::Object { packages }) => packages,
        None => &[],
    };
    let pnpm_globs = pnpm_workspace.map_or(&[][..], |config| config.packages.as_slice());
    let mut globs = Vec::with_capacity(package_json_globs.len() + pnpm_globs.len());
    let mut seen = HashSet::with_capacity(globs.capacity());
    for glob in package_json_globs.iter().chain(pnpm_globs) {
        if seen.insert(glob.as_str()) {
            globs.push(glob.clone());
        }
    }
    globs
}

/// Read a workspace root manifest and merge root configuration from
/// `pnpm-workspace.yaml` without discovering member packages.
pub fn read_workspace_root_package(root: &Path) -> Result<PackageJson, WorkspaceError> {
    read_workspace_root(root).map(|(package, _)| package)
}

fn read_workspace_root(
    root: &Path,
) -> Result<(PackageJson, Option<PnpmWorkspaceConfig>), WorkspaceError> {
    let mut root_package = read_package_json(&root.join("package.json"))?;
    let pnpm_workspace = read_pnpm_workspace(&root.join("pnpm-workspace.yaml"))?;
    if let Some(config) = pnpm_workspace.as_ref() {
        merge_pnpm_workspace_config(&mut root_package, config);
    }
    Ok((root_package, pnpm_workspace))
}

fn read_workspace_root_from_open_dir(
    root_path: &Path,
    root_dir: &cap_std::fs::Dir,
) -> Result<(PackageJson, Option<PnpmWorkspaceConfig>), WorkspaceError> {
    let mut root_package = read_package_json_from_open_dir(
        root_dir,
        Path::new("package.json"),
        &root_path.join("package.json"),
    )?;
    let pnpm_workspace = read_pnpm_workspace_from_open_dir(
        root_dir,
        Path::new("pnpm-workspace.yaml"),
        &root_path.join("pnpm-workspace.yaml"),
    )?;
    if let Some(config) = pnpm_workspace.as_ref() {
        merge_pnpm_workspace_config(&mut root_package, config);
    }
    Ok((root_package, pnpm_workspace))
}

fn read_package_json_from_open_dir(
    directory: &cap_std::fs::Dir,
    relative: &Path,
    display_path: &Path,
) -> Result<PackageJson, WorkspaceError> {
    let content = read_text_from_open_dir(
        directory,
        relative,
        display_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        false,
    )?
    .ok_or_else(|| WorkspaceError::NotFound(display_path.display().to_string()))?;
    serde_json::from_str(lpm_common::strip_utf8_bom_str(&content)).map_err(|error| {
        WorkspaceError::Parse(format!(
            "failed to parse {}: {error}",
            display_path.display()
        ))
    })
}

fn read_pnpm_workspace_from_open_dir(
    directory: &cap_std::fs::Dir,
    relative: &Path,
    display_path: &Path,
) -> Result<Option<PnpmWorkspaceConfig>, WorkspaceError> {
    let Some(content) = read_text_from_open_dir(
        directory,
        relative,
        display_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        true,
    )?
    else {
        return Ok(None);
    };
    if content.trim().is_empty() {
        return Ok(Some(PnpmWorkspaceConfig::default()));
    }
    let manifest =
        serde_yaml::from_str::<Option<PnpmWorkspaceManifest>>(&content).map_err(|error| {
            WorkspaceError::Parse(format!(
                "failed to parse pnpm workspace manifest {}: {error}",
                display_path.display()
            ))
        })?;
    Ok(Some(manifest.unwrap_or_default().into_config()))
}

fn read_text_from_open_dir(
    directory: &cap_std::fs::Dir,
    relative: &Path,
    display_path: &Path,
    max_bytes: u64,
    optional: bool,
) -> Result<Option<String>, WorkspaceError> {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = match directory.open_with(relative, &options) {
        Ok(file) => file,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(WorkspaceError::NotFound(display_path.display().to_string()));
        }
        Err(error) => {
            return Err(WorkspaceError::Io(format!(
                "failed to open {} safely: {error}",
                display_path.display()
            )));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        WorkspaceError::Io(format!(
            "failed to inspect {}: {error}",
            display_path.display()
        ))
    })?;
    if !metadata.is_file() || metadata_is_link_or_reparse(&metadata) {
        return Err(WorkspaceError::Io(format!(
            "workspace manifest {} is not a safe regular file",
            display_path.display()
        )));
    }
    lpm_common::read_text_file_capped_from_open_file_with_known_size(
        file.into_std(),
        display_path,
        max_bytes,
        metadata.len(),
    )
    .map(Some)
    .map_err(|error| WorkspaceError::Io(error.to_string()))
}

fn open_directory_nofollow(path: &Path) -> std::io::Result<cap_std::fs::Dir> {
    use cap_fs_ext::DirExt as _;

    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "workspace candidate path must be absolute",
        ));
    }
    let root = path
        .ancestors()
        .last()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "workspace candidate path has no filesystem root",
            )
        })?;
    let mut directory = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    let relative = path.strip_prefix(root).map_err(std::io::Error::other)?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "workspace candidate path contains an unsafe component",
            ));
        };
        directory = directory.open_dir_nofollow(name)?;
    }
    Ok(directory)
}

/// Walk up from `start_dir` to find the nearest ancestor directory
/// that contains a `package.json` and return that directory.
///
/// Matches npm / pnpm / yarn / bun behavior for the "I'm in a subdir
/// of the project, run install here" case. Returns `None` when no
/// ancestor manifest exists all the way to the filesystem root.
///
/// `discover_workspace` is the right call when only a workspace root
/// (one that declares `workspaces` globs or has a sibling
/// `pnpm-workspace.yaml`) counts as a match. This helper is the
/// looser counterpart — any `package.json` qualifies — used by the
/// install dispatcher so a bare `lpm install` or `lpm i <pkg>` in a
/// non-workspace subdirectory still finds the project root.
pub fn find_project_root(start_dir: &Path) -> Option<PathBuf> {
    let mut current = start_dir.to_path_buf();
    loop {
        if current.join("package.json").is_file() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct PnpmWorkspaceManifest {
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    catalog: HashMap<String, String>,
    #[serde(default)]
    catalogs: HashMap<String, HashMap<String, String>>,
    #[serde(default, rename = "cleanupUnusedCatalogs")]
    cleanup_unused_catalogs: Option<bool>,
}

#[derive(Debug, Default)]
struct PnpmWorkspaceConfig {
    packages: Vec<String>,
    catalogs: HashMap<String, HashMap<String, String>>,
    cleanup_unused_catalogs: Option<bool>,
}

impl PnpmWorkspaceManifest {
    fn into_config(self) -> PnpmWorkspaceConfig {
        let mut catalogs = self.catalogs;
        if !self.catalog.is_empty() {
            let default_catalog = catalogs.entry("default".to_string()).or_default();
            for (package, range) in self.catalog {
                default_catalog.entry(package).or_insert(range);
            }
        }

        PnpmWorkspaceConfig {
            packages: self.packages,
            catalogs,
            cleanup_unused_catalogs: self.cleanup_unused_catalogs,
        }
    }
}

/// Read pnpm-workspace.yaml and extract package globs plus root catalogs.
fn read_pnpm_workspace(path: &Path) -> Result<Option<PnpmWorkspaceConfig>, WorkspaceError> {
    let content =
        match lpm_common::read_text_file_capped(path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES) {
            Ok(content) => content,
            Err(lpm_common::BoundedReadError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(WorkspaceError::Io(error.to_string())),
        };

    if content.trim().is_empty() {
        return Ok(Some(PnpmWorkspaceConfig::default()));
    }

    let manifest: Option<PnpmWorkspaceManifest> = serde_yaml::from_str(&content).map_err(|e| {
        WorkspaceError::Parse(format!(
            "failed to parse pnpm workspace manifest {}: {e}",
            path.display()
        ))
    })?;

    Ok(Some(manifest.unwrap_or_default().into_config()))
}

fn merge_pnpm_workspace_config(root_package: &mut PackageJson, config: &PnpmWorkspaceConfig) {
    for (catalog_name, catalog) in &config.catalogs {
        let target = root_package
            .catalogs
            .entry(catalog_name.clone())
            .or_insert_with(|| HashMap::with_capacity(catalog.len()));
        for (package, range) in catalog {
            if target.contains_key(package) {
                tracing::warn!(
                    catalog = %catalog_name,
                    package = %package,
                    "package.json catalog entry overrides pnpm-workspace.yaml catalog entry",
                );
            } else {
                target.insert(package.clone(), range.clone());
            }
        }
    }

    if let Some(cleanup_unused_catalogs) = config.cleanup_unused_catalogs {
        let lpm = root_package.lpm.get_or_insert_with(LpmConfig::default);
        if lpm.cleanup_unused_catalogs.is_none() {
            lpm.cleanup_unused_catalogs = Some(cleanup_unused_catalogs);
        }
    }
}

/// validate that a workspace glob pattern is a relative path
/// without `..` components and without absolute-path syntax.
///
/// `Path::join("/abs")` discards the prefix, so `"workspaces":
/// ["/etc/*"]` literally walks `/etc/`; `"workspaces": ["../*"]`
/// mounts sibling repositories as workspace members. Matched
/// `package.json` files are read and folded into the install-hash;
/// sibling-project deps would otherwise materialize into the
/// current project's `node_modules`. The pattern boundary is the
/// only place to refuse this before workspace traversal begins.
fn validate_workspace_glob(pattern: &str) -> Result<(), WorkspaceError> {
    if pattern.is_empty() {
        return Err(WorkspaceError::Parse("empty workspace glob pattern".into()));
    }
    let p = Path::new(pattern);
    if p.is_absolute() {
        return Err(WorkspaceError::Parse(format!(
            "workspace glob '{pattern}' is absolute — must be relative to the project root"
        )));
    }
    // On Windows, `C:foo` is rooted (drive-relative) without being
    // absolute. Block that shape too by rejecting any prefix component.
    #[cfg(windows)]
    if p.components()
        .any(|c| matches!(c, std::path::Component::Prefix(_)))
    {
        return Err(WorkspaceError::Parse(format!(
            "workspace glob '{pattern}' contains a drive prefix — must be relative to the project root"
        )));
    }
    for comp in p.components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return Err(WorkspaceError::Parse(format!(
                "workspace glob '{pattern}' contains '..' — must stay within the project root"
            )));
        }
        if matches!(comp, std::path::Component::RootDir) {
            return Err(WorkspaceError::Parse(format!(
                "workspace glob '{pattern}' starts at root — must be relative to the project root"
            )));
        }
    }
    Ok(())
}

/// emit a `tracing::warn` for every workspace member whose
/// `package.json` declares its own `catalogs` field. The install
/// pipeline only honours `root_package.catalogs`; member-level
/// catalogs are silently ignored today. The data shape allows them
/// because `PackageJson::catalogs` is a single field shared by both
/// root and members, so a future routing-bug or refactor could start
/// resolving per-member with no surface signal that the source was
/// authored as if it were active. The warn surfaces the silent-drop
/// at discovery time so a malicious / mistaken member-level catalog
/// is visible in operator logs before any resolve runs.
fn warn_on_member_catalogs(members: &[WorkspaceMember]) {
    for member in members {
        if !member.package.catalogs.is_empty() {
            tracing::warn!(
                member_path = %member.path.display(),
                catalog_count = member.package.catalogs.len(),
                "workspace member declares its own `catalogs` field — silently ignored by the resolver. Only the root package's `catalogs` are honoured . Move the entries to the root package.json or remove the field to silence this warning.",
            );
        }
    }
}

/// Discover workspace member packages matching the given glob patterns.
fn discover_members(root: &Path, globs: &[String]) -> Result<Vec<WorkspaceMember>, WorkspaceError> {
    let mut manifest_paths = Vec::new();
    let mut exclusions = Vec::new();
    for pattern in globs {
        let Some(excluded) = pattern.strip_prefix('!') else {
            let workspace_glob = WorkspaceGlob::compile(root, pattern)?;
            workspace_glob.collect_manifest_paths(root, &mut manifest_paths)?;
            continue;
        };
        exclusions.push(WorkspaceGlob::compile(root, excluded)?);
    }
    manifest_paths.retain(|manifest| {
        let directory = manifest.parent().expect("workspace manifest has a parent");
        let relative = directory.strip_prefix(root).unwrap_or(directory);
        !exclusions
            .iter()
            .any(|exclusion| exclusion.matches_relative_directory(relative))
    });
    manifest_paths.sort();
    manifest_paths.dedup();

    let mut members = Vec::with_capacity(manifest_paths.len());
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    for pkg_json_path in manifest_paths {
        let canonical_match = pkg_json_path
            .canonicalize()
            .unwrap_or_else(|_| pkg_json_path.clone());
        if !canonical_match.starts_with(&canonical_root) {
            tracing::warn!(
                matched = %pkg_json_path.display(),
                canonical = %canonical_match.display(),
                canonical_root = %canonical_root.display(),
                "skipping workspace member outside project root"
            );
            continue;
        }

        let member_dir = pkg_json_path
            .parent()
            .expect("workspace manifest has a parent")
            .to_path_buf();
        let package = read_package_json(&pkg_json_path)?;
        members.push(WorkspaceMember {
            path: member_dir,
            package,
        });
    }

    Ok(members)
}

fn discover_members_from_open_root(
    root_path: &Path,
    root_dir: &cap_std::fs::Dir,
    globs: &[String],
) -> Result<Vec<WorkspaceMember>, WorkspaceError> {
    let (inclusions, exclusions) = compile_workspace_globs(root_path, globs)?;
    let member_scan =
        discover_member_paths_from_open_root(root_path, root_dir, &inclusions, &exclusions)?;
    let mut members = Vec::with_capacity(member_scan.member_paths.len());
    for relative in member_scan.member_paths {
        let directory = open_relative_directory(root_dir, &relative)?.ok_or_else(|| {
            WorkspaceError::NotFound(root_path.join(&relative).display().to_string())
        })?;
        let display_path = root_path.join(&relative).join("package.json");
        let package =
            read_package_json_from_open_dir(&directory, Path::new("package.json"), &display_path)?;
        members.push(WorkspaceMember {
            path: root_path.join(relative),
            package,
        });
    }
    Ok(members)
}

fn discover_member_paths_from_open_root(
    root_path: &Path,
    root_dir: &cap_std::fs::Dir,
    inclusions: &[WorkspaceGlob],
    exclusions: &[WorkspaceGlob],
) -> Result<WorkspaceMemberScan, WorkspaceError> {
    let mut members = std::collections::BTreeSet::new();
    let mut directories = std::collections::BTreeSet::new();
    let match_options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    for inclusion in inclusions {
        let scan_relative = inclusion
            .scan_root
            .strip_prefix(root_path)
            .map_err(|_| {
                WorkspaceError::Parse(format!(
                    "workspace scan root {} is outside {}",
                    inclusion.scan_root.display(),
                    root_path.display()
                ))
            })?
            .to_path_buf();
        if open_relative_directory(root_dir, &scan_relative)?.is_none() {
            continue;
        }
        let mut pending = vec![(scan_relative, inclusion.scan_root_depth)];
        while let Some((relative, depth)) = pending.pop() {
            let Some(directory) = open_relative_directory(root_dir, &relative)? else {
                continue;
            };
            directories.insert(relative.clone());
            if inclusion.matches_directory(&relative, match_options)
                && !exclusions
                    .iter()
                    .any(|exclusion| exclusion.matches_relative_directory(&relative))
            {
                let display_path = root_path.join(&relative).join("package.json");
                match directory.symlink_metadata("package.json") {
                    Ok(metadata)
                        if metadata.is_file() && !metadata_is_link_or_reparse(&metadata) =>
                    {
                        members.insert(relative.clone());
                    }
                    Ok(_) => {
                        return Err(WorkspaceError::Io(format!(
                            "workspace manifest {} is not a safe regular file",
                            display_path.display()
                        )));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(WorkspaceError::Io(format!(
                            "failed to inspect {}: {error}",
                            display_path.display()
                        )));
                    }
                }
            }
            if inclusion
                .max_depth
                .is_some_and(|max_depth| depth >= max_depth)
            {
                continue;
            }
            let entries = directory.entries().map_err(|error| {
                WorkspaceError::Io(format!(
                    "failed to read {}: {error}",
                    root_path.join(&relative).display()
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(|error| {
                    WorkspaceError::Io(format!(
                        "failed to read {}: {error}",
                        root_path.join(&relative).display()
                    ))
                })?;
                let name = entry.file_name();
                if name == "node_modules" {
                    continue;
                }
                let metadata = directory
                    .symlink_metadata(Path::new(&name))
                    .map_err(|error| {
                        WorkspaceError::Io(format!(
                            "failed to inspect {}: {error}",
                            root_path.join(&relative).join(&name).display()
                        ))
                    })?;
                if metadata_is_link_or_reparse(&metadata) || !metadata.is_dir() {
                    continue;
                }
                pending.push((relative.join(name), depth + 1));
            }
        }
    }
    Ok(WorkspaceMemberScan {
        member_paths: members.into_iter().collect(),
        directory_paths: directories.into_iter().collect(),
    })
}

fn open_relative_directory(
    root: &cap_std::fs::Dir,
    relative: &Path,
) -> Result<Option<cap_std::fs::Dir>, WorkspaceError> {
    use cap_fs_ext::DirExt as _;

    let mut directory = root.try_clone().map_err(|error| {
        WorkspaceError::Io(format!("failed to clone workspace root handle: {error}"))
    })?;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        match directory.open_dir_nofollow(name) {
            Ok(child) => directory = child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(WorkspaceError::Io(format!(
                    "failed to open workspace directory {} safely: {error}",
                    relative.display()
                )));
            }
        }
    }
    Ok(Some(directory))
}

#[cfg(windows)]
fn metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_link_or_reparse(metadata: &cap_std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

struct WorkspaceGlob {
    pattern: glob::Pattern,
    scan_root: PathBuf,
    scan_root_depth: usize,
    max_depth: Option<usize>,
}

impl WorkspaceGlob {
    fn compile(root: &Path, raw: &str) -> Result<Self, WorkspaceError> {
        validate_workspace_glob(raw)?;
        let mut normalized = PathBuf::new();
        for component in Path::new(raw).components() {
            if let std::path::Component::Normal(value) = component {
                normalized.push(value);
            }
        }
        if normalized.as_os_str().is_empty() {
            normalized.push(".");
        }
        let pattern = glob::Pattern::new(&normalized.to_string_lossy()).map_err(|error| {
            WorkspaceError::Parse(format!("invalid glob pattern '{raw}': {error}"))
        })?;
        let components: Vec<_> = normalized.components().collect();
        let literal_components = components
            .iter()
            .take_while(|component| !contains_glob_metacharacters(component.as_os_str()))
            .count();
        let mut scan_root = root.to_path_buf();
        for component in components.iter().take(literal_components) {
            scan_root.push(component.as_os_str());
        }
        let max_depth = components
            .iter()
            .all(|component| !component.as_os_str().to_string_lossy().contains("**"))
            .then_some(components.len());
        Ok(Self {
            pattern,
            scan_root,
            scan_root_depth: literal_components,
            max_depth,
        })
    }

    fn collect_manifest_paths(
        &self,
        root: &Path,
        manifests: &mut Vec<PathBuf>,
    ) -> Result<(), WorkspaceError> {
        match std::fs::symlink_metadata(&self.scan_root) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(WorkspaceError::Io(format!(
                    "failed to inspect {}: {error}",
                    self.scan_root.display()
                )));
            }
        }
        let match_options = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: false,
        };
        let mut pending = vec![(self.scan_root.clone(), self.scan_root_depth)];
        while let Some((directory, depth)) = pending.pop() {
            let relative = directory.strip_prefix(root).unwrap_or(&directory);
            if self.matches_directory(relative, match_options) {
                let manifest = directory.join("package.json");
                if manifest.is_file() {
                    manifests.push(manifest);
                }
            }
            if self.max_depth.is_some_and(|max_depth| depth >= max_depth) {
                continue;
            }
            let entries = std::fs::read_dir(&directory).map_err(|error| {
                WorkspaceError::Io(format!("failed to read {}: {error}", directory.display()))
            })?;
            for entry in entries {
                let entry = entry.map_err(|error| {
                    WorkspaceError::Io(format!("failed to read {}: {error}", directory.display()))
                })?;
                let file_type = entry.file_type().map_err(|error| {
                    WorkspaceError::Io(format!(
                        "failed to inspect {}: {error}",
                        entry.path().display()
                    ))
                })?;
                if file_type.is_dir() && entry.file_name() != "node_modules" {
                    pending.push((entry.path(), depth + 1));
                }
            }
        }
        Ok(())
    }

    fn matches_directory(&self, relative: &Path, options: glob::MatchOptions) -> bool {
        if self.pattern.matches_path_with(relative, options) {
            return true;
        }
        let relative = relative.to_string_lossy();
        let mut with_separator = String::with_capacity(relative.len() + 1);
        with_separator.push_str(&relative);
        with_separator.push(std::path::MAIN_SEPARATOR);
        self.pattern.matches_with(&with_separator, options)
    }

    fn matches_relative_directory(&self, relative: &Path) -> bool {
        self.matches_directory(
            relative,
            glob::MatchOptions {
                case_sensitive: true,
                require_literal_separator: true,
                require_literal_leading_dot: false,
            },
        )
    }
}

fn contains_glob_metacharacters(component: &std::ffi::OsStr) -> bool {
    component
        .to_string_lossy()
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'['))
}

fn has_intermediate_non_member_package_json(
    start: &Path,
    root: &Path,
    members: &[WorkspaceMember],
) -> bool {
    let mut current = Some(start);

    while let Some(dir) = current {
        if dir == root {
            return false;
        }

        if dir.join("package.json").exists() && !members.iter().any(|member| member.path == dir) {
            return true;
        }

        current = dir.parent();
    }

    false
}

/// Collect all production dependencies across the workspace.
///
/// Merges root + member dependencies. For overlapping deps, the root's
/// version range takes precedence.
pub fn collect_all_dependencies(workspace: &Workspace) -> HashMap<String, String> {
    let mut all_deps: HashMap<String, String> = HashMap::new();

    // Members first (root overrides)
    for member in &workspace.members {
        for (name, range) in &member.package.dependencies {
            all_deps.insert(name.clone(), range.clone());
        }
    }

    // Root overrides members
    for (name, range) in &workspace.root_package.dependencies {
        all_deps.insert(name.clone(), range.clone());
    }

    all_deps
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_package_json(dir: &Path, content: &str) {
        fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn discover_no_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{"name": "single-package", "dependencies": {}}"#,
        );

        let result = discover_workspace(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn discover_npm_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*"]
            }"#,
        );

        // Create a member package
        let member_dir = dir.path().join("packages/my-lib");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{"name": "@lpm.dev/test.my-lib", "dependencies": {"react": "^19.0.0"}}"#,
        );

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        assert_eq!(ws.members.len(), 1);
        assert_eq!(
            ws.members[0].package.name.as_deref(),
            Some("@lpm.dev/test.my-lib")
        );
    }

    #[test]
    fn open_root_discovery_matches_workspace_members_and_catalogs() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*", "!packages/private"],
                "catalogs": {"default": {"react": "^19.0.0"}}
            }"#,
        );
        for (path, name) in [("packages/app", "app"), ("packages/private", "private")] {
            let member = dir.path().join(path);
            fs::create_dir_all(&member).unwrap();
            create_package_json(
                &member,
                &format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
            );
        }
        let root =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();

        let workspace =
            discover_workspace_from_open_root(dir.path(), &root, &dir.path().join("packages/app"))
                .unwrap()
                .unwrap();

        assert_eq!(workspace.members.len(), 1);
        assert_eq!(workspace.members[0].package.name.as_deref(), Some("app"));
        assert_eq!(
            workspace.root_package.catalogs["default"]["react"],
            "^19.0.0"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_root_discovery_rejects_a_fifo_manifest_promptly() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::tempdir().unwrap();
        let package_json = dir.path().join("package.json");
        let path = std::ffi::CString::new(package_json.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let root =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();
        let display_root = dir.path().to_path_buf();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = discover_workspace_from_open_root(&display_root, &root, &display_root)
                .map(|_| ())
                .map_err(|error| error.to_string());
            sender.send(result).unwrap();
        });
        let result = match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(result) => result,
            Err(error) => {
                let writer = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&package_json)
                    .unwrap();
                drop(writer);
                let _ = receiver.recv_timeout(std::time::Duration::from_secs(1));
                worker.join().unwrap();
                panic!("open-root workspace discovery blocked on a FIFO: {error}");
            }
        };
        worker.join().unwrap();

        let error = result.expect_err("a FIFO workspace manifest must be rejected");
        assert!(error.contains("package.json"), "{error}");
    }

    #[test]
    fn safe_workspace_root_selection_returns_the_opened_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        create_package_json(&root, r#"{"name":"root","workspaces":["packages/*"]}"#);
        let project = root.join("packages/app");
        fs::create_dir_all(&project).unwrap();
        create_package_json(&project, r#"{"name":"app","version":"1.0.0"}"#);
        let project_dir =
            cap_std::fs::Dir::open_ambient_dir(&project, cap_std::ambient_authority()).unwrap();

        let selected = find_workspace_root_from_open_project(&project, &project_dir)
            .unwrap()
            .expect("the project is a workspace member");

        assert_eq!(selected.path(), root);
        assert!(selected.directory().dir_metadata().unwrap().is_dir());
    }

    #[test]
    fn workspace_root_selection_rejects_a_project_handle_from_another_generation() {
        let dir = tempfile::tempdir().unwrap();
        let temp_root = dir.path().canonicalize().unwrap();
        let workspace = temp_root.join("workspace");
        let project = workspace.join("packages/app");
        fs::create_dir_all(&project).unwrap();
        create_package_json(&workspace, r#"{"name":"original-root"}"#);
        create_package_json(&project, r#"{"name":"original-app","version":"1.0.0"}"#);
        let project_dir =
            cap_std::fs::Dir::open_ambient_dir(&project, cap_std::ambient_authority()).unwrap();

        fs::rename(&workspace, temp_root.join("displaced-workspace")).unwrap();
        fs::create_dir_all(&project).unwrap();
        create_package_json(
            &workspace,
            r#"{"name":"replacement-root","workspaces":["packages/*"]}"#,
        );
        create_package_json(&project, r#"{"name":"replacement-app","version":"9.9.9"}"#);

        let error = find_workspace_root_from_open_project(&project, &project_dir)
            .err()
            .expect("a replacement ancestor must not contain the retained project handle")
            .to_string();

        assert!(error.contains("selected project"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn safe_workspace_root_selection_rejects_a_linked_pnpm_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        create_package_json(&root, r#"{"name":"root"}"#);
        let external = root.join("external-pnpm-workspace.yaml");
        fs::write(&external, "packages:\n  - packages/*\n").unwrap();
        std::os::unix::fs::symlink(&external, root.join("pnpm-workspace.yaml")).unwrap();
        let project = root.join("packages/app");
        fs::create_dir_all(&project).unwrap();
        create_package_json(&project, r#"{"name":"app","version":"1.0.0"}"#);
        let project_dir =
            cap_std::fs::Dir::open_ambient_dir(&project, cap_std::ambient_authority()).unwrap();

        let error = find_workspace_root_from_open_project(&project, &project_dir)
            .err()
            .expect("linked pnpm workspace metadata must be rejected")
            .to_string();

        assert!(error.contains("pnpm-workspace.yaml"), "{error}");
    }

    #[test]
    fn discover_workspace_object_form() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": { "packages": ["apps/*"] }
            }"#,
        );

        let app_dir = dir.path().join("apps/web");
        fs::create_dir_all(&app_dir).unwrap();
        create_package_json(&app_dir, r#"{"name": "web"}"#);

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        assert_eq!(ws.members.len(), 1);
    }

    #[test]
    fn discover_workspace_rejects_duplicate_member_package_names() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(dir.path(), r#"{"name":"root","workspaces":["packages/*"]}"#);
        let first = dir.path().join("packages/first");
        let second = dir.path().join("packages/second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        create_package_json(&first, r#"{"name":"duplicate"}"#);
        create_package_json(&second, r#"{"name":"duplicate"}"#);

        let error = discover_workspace(dir.path())
            .expect_err("duplicate workspace package names must be rejected");
        let message = error.to_string();

        assert!(message.contains("duplicate"), "{message}");
        assert!(message.contains(&first.display().to_string()), "{message}");
        assert!(message.contains(&second.display().to_string()), "{message}");
    }

    #[test]
    fn discover_workspace_rejects_root_and_member_package_name_collision() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{"name":"duplicate","workspaces":["packages/*"]}"#,
        );
        let member = dir.path().join("packages/member");
        fs::create_dir_all(&member).unwrap();
        create_package_json(&member, r#"{"name":"duplicate"}"#);

        let error = discover_workspace(dir.path())
            .expect_err("the workspace root and a member must not share a package name");
        let message = error.to_string();

        assert!(
            message.contains(&dir.path().display().to_string()),
            "{message}"
        );
        assert!(message.contains(&member.display().to_string()), "{message}");
    }

    #[test]
    fn discover_pnpm_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(dir.path(), r#"{"name": "monorepo"}"#);

        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n",
        )
        .unwrap();

        let member_dir = dir.path().join("packages/utils");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(&member_dir, r#"{"name": "utils"}"#);

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        assert_eq!(ws.members.len(), 1);
    }

    #[test]
    fn discover_workspace_combines_package_json_and_pnpm_workspace_members() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{"name":"monorepo","workspaces":["packages/*"]}"#,
        );
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - 'turbopack/packages/*'\n",
        )
        .unwrap();

        let package_dir = dir.path().join("packages/app");
        fs::create_dir_all(&package_dir).unwrap();
        create_package_json(&package_dir, r#"{"name":"app"}"#);
        let turbopack_dir = dir.path().join("turbopack/packages/devlow-bench");
        fs::create_dir_all(&turbopack_dir).unwrap();
        create_package_json(&turbopack_dir, r#"{"name":"devlow-bench"}"#);

        let workspace = discover_workspace(dir.path()).unwrap().unwrap();
        let member_names: Vec<_> = workspace
            .members
            .iter()
            .filter_map(|member| member.package.name.as_deref())
            .collect();

        assert_eq!(member_names, ["app", "devlow-bench"]);
    }

    #[test]
    fn discover_pnpm_workspace_excludes_members_matching_negated_globs() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(dir.path(), r#"{"name":"monorepo"}"#);
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/**'\n  - '!**/dist-*'\n",
        )
        .unwrap();

        let member_dir = dir.path().join("packages/member");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(&member_dir, r#"{"name":"member"}"#);
        let excluded_dir = dir.path().join("packages/dist-generated");
        fs::create_dir_all(&excluded_dir).unwrap();
        create_package_json(&excluded_dir, r#"{"name":"dist-generated"}"#);

        let workspace = discover_workspace(dir.path()).unwrap().unwrap();
        let names: Vec<_> = workspace
            .members
            .iter()
            .filter_map(|member| member.package.name.as_deref())
            .collect();

        assert_eq!(names, ["member"]);
    }

    #[test]
    fn discover_workspace_ignores_member_nohoist_object_without_package_globs() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{"name":"monorepo","workspaces":{"packages":["apps/*"]}}"#,
        );
        let member_dir = dir.path().join("apps/webhook");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{"name":"@fixture/webhook","workspaces":{"nohoist":["socket.io"]}}"#,
        );

        let workspace = discover_workspace(&member_dir).unwrap().unwrap();

        assert_eq!(workspace.root, dir.path());
        assert_eq!(workspace.members.len(), 1);
        assert_eq!(
            workspace.members[0].package.name.as_deref(),
            Some("@fixture/webhook")
        );
    }

    #[test]
    fn read_workspace_root_package_merges_pnpm_configuration_without_discovering_members() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(dir.path(), r#"{"name":"monorepo"}"#);
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/**'\ncatalog:\n  react: ^19.0.0\n",
        )
        .unwrap();

        let package = read_workspace_root_package(dir.path()).unwrap();

        assert_eq!(package.catalogs["default"]["react"], "^19.0.0");
    }

    #[cfg(unix)]
    #[test]
    fn discover_workspace_ignores_node_modules_symlink_cycles() {
        let directory = tempfile::tempdir().unwrap();
        create_package_json(directory.path(), r#"{"name":"root","private":true}"#);
        fs::write(
            directory.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'playground/**'\n",
        )
        .unwrap();
        let member = directory.path().join("playground/alias");
        fs::create_dir_all(member.join("node_modules/@vitejs")).unwrap();
        create_package_json(
            &member,
            r#"{"name":"@vitejs/test-alias","version":"0.0.0"}"#,
        );
        std::os::unix::fs::symlink(
            member.canonicalize().unwrap(),
            member.join("node_modules/@vitejs/test-alias"),
        )
        .unwrap();

        let workspace = discover_workspace(directory.path()).unwrap().unwrap();

        assert_eq!(workspace.members.len(), 1);
    }

    #[test]
    fn discover_workspace_recursive_globs_include_their_zero_depth_tail() {
        let directory = tempfile::tempdir().unwrap();
        create_package_json(directory.path(), r#"{"name":"root","private":true}"#);
        fs::write(
            directory.path().join("pnpm-workspace.yaml"),
            "packages:\n  - 'playground/**'\n  - 'packages/**/__tests__/**'\n",
        )
        .unwrap();
        fs::create_dir_all(directory.path().join("playground")).unwrap();
        create_package_json(
            &directory.path().join("playground"),
            r#"{"name":"playground"}"#,
        );
        fs::create_dir_all(directory.path().join("packages/vite/src/node/__tests__")).unwrap();
        create_package_json(
            &directory.path().join("packages/vite/src/node/__tests__"),
            r#"{"name":"vite-tests"}"#,
        );

        let workspace = discover_workspace(directory.path()).unwrap().unwrap();
        let names: Vec<_> = workspace
            .members
            .iter()
            .filter_map(|member| member.package.name.as_deref())
            .collect();

        assert_eq!(names, ["vite-tests", "playground"]);
    }

    #[test]
    fn discover_workspace_from_member_directory_walks_past_member_package_json() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*"]
            }"#,
        );

        let member_dir = dir.path().join("packages/app");
        let nested_dir = member_dir.join("src/components");
        fs::create_dir_all(&nested_dir).unwrap();
        create_package_json(&member_dir, r#"{"name": "app"}"#);

        let ws = discover_workspace(&nested_dir)
            .unwrap()
            .expect("expected workspace root discovery from member subdirectory");

        assert_eq!(ws.root, dir.path());
        assert_eq!(ws.members.len(), 1);
        assert_eq!(ws.members[0].package.name.as_deref(), Some("app"));
    }

    #[test]
    fn find_workspace_root_does_not_parse_unrelated_member_manifests() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{"name":"monorepo","workspaces":["packages/*"]}"#,
        );
        let app = dir.path().join("packages/app");
        let broken = dir.path().join("packages/broken");
        fs::create_dir_all(&app).unwrap();
        fs::create_dir_all(&broken).unwrap();
        create_package_json(&app, r#"{"name":"app"}"#);
        fs::write(broken.join("package.json"), "{ invalid").unwrap();

        let root = find_workspace_root(&app).unwrap();

        assert_eq!(root.as_deref(), Some(dir.path()));
        assert!(discover_workspace(&app).is_err());
    }

    #[test]
    fn find_workspace_root_does_not_attach_an_unlisted_nested_package() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{"name":"monorepo","workspaces":["packages/*"]}"#,
        );
        let local = dir.path().join("tools/local-project");
        fs::create_dir_all(&local).unwrap();
        create_package_json(&local, r#"{"name":"local-project"}"#);

        assert!(find_workspace_root(&local).unwrap().is_none());
    }

    #[test]
    fn discover_workspace_does_not_attach_unlisted_nested_package_to_outer_workspace() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*"]
            }"#,
        );

        let member_dir = dir.path().join("packages/app");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(&member_dir, r#"{"name": "app"}"#);

        let unrelated_dir = dir.path().join("tools/local-project");
        fs::create_dir_all(&unrelated_dir).unwrap();
        create_package_json(&unrelated_dir, r#"{"name": "local-project"}"#);

        let result = discover_workspace(&unrelated_dir).unwrap();
        assert!(
            result.is_none(),
            "nested package not matched by workspace globs should not attach to outer workspace"
        );
    }

    #[test]
    fn discover_workspace_from_non_member_subdirectory_under_root_returns_root() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "monorepo",
                "workspaces": ["packages/*"]
            }"#,
        );

        let member_dir = dir.path().join("packages/app");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(&member_dir, r#"{"name": "app"}"#);

        let tooling_dir = dir.path().join("tools/scripts");
        fs::create_dir_all(&tooling_dir).unwrap();

        let ws = discover_workspace(&tooling_dir)
            .unwrap()
            .expect("workspace root should still be discoverable from non-member subdirectories");

        assert_eq!(ws.root, dir.path());
        assert_eq!(ws.members.len(), 1);
        assert_eq!(ws.members[0].package.name.as_deref(), Some("app"));
    }

    #[test]
    fn collect_all_deps_merges() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "root",
                "workspaces": ["packages/*"],
                "dependencies": {"shared": "^2.0.0"}
            }"#,
        );

        let member_dir = dir.path().join("packages/a");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{"name": "a", "dependencies": {"shared": "^1.0.0", "only-a": "^1.0.0"}}"#,
        );

        let ws = discover_workspace(dir.path()).unwrap().unwrap();
        let all = collect_all_dependencies(&ws);

        // Root's version wins for "shared"
        assert_eq!(all.get("shared").unwrap(), "^2.0.0");
        // Member-only dep is included
        assert!(all.contains_key("only-a"));
    }

    // ── Workspace glob escape ─────────────────────────────

    /// a `..` segment in a workspace glob is the sibling-project
    /// injection shape — refuse at the manifest boundary so the glob
    /// library never gets to walk parent directories.
    #[test]
    fn discover_workspace_refuses_glob_with_parent_dir_segment() {
        let err = validate_workspace_glob("../sibling/*").unwrap_err();
        assert!(
            format!("{:?}", err).contains("'..'"),
            "error must mention the '..' rejection: {err:?}"
        );
    }

    /// `PathBuf::join("/abs")` discards the project-root prefix
    /// and walks `/abs` instead. Absolute globs must be refused.
    #[test]
    fn discover_workspace_refuses_absolute_glob() {
        // Unix absolute path. Windows test below covers the
        // drive-prefix variant.
        let err = validate_workspace_glob("/etc/*").unwrap_err();
        assert!(format!("{:?}", err).contains("absolute"));
    }

    /// legitimate relative globs still parse.
    #[test]
    fn discover_workspace_accepts_relative_globs() {
        validate_workspace_glob("packages/*").unwrap();
        validate_workspace_glob("apps/*/web").unwrap();
        validate_workspace_glob("./crates/*").unwrap();
        validate_workspace_glob("internal").unwrap();
    }

    /// nested `..` deeper in the pattern is also refused. The
    /// `Path::components()` scan walks every segment.
    #[test]
    fn discover_workspace_refuses_nested_parent_dir_segment() {
        let err = validate_workspace_glob("packages/../../etc/*").unwrap_err();
        assert!(format!("{:?}", err).contains("'..'"));
    }

    /// empty pattern would degenerate to scanning the project
    /// root + every subdirectory — refuse so the operator gets a
    /// clear error rather than a surprising O(n) cost.
    #[test]
    fn discover_workspace_refuses_empty_glob() {
        let err = validate_workspace_glob("").unwrap_err();
        assert!(format!("{:?}", err).contains("empty"));
    }

    /// end-to-end — a `package.json` declaring
    /// `"workspaces": ["../*"]` must fail at `discover_workspace`,
    /// not silently mount sibling-project deps. Real attack shape.
    #[test]
    fn discover_workspace_refuses_workspace_with_parent_glob() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "victim",
                "workspaces": ["../*"]
            }"#,
        );
        let err = discover_workspace(dir.path()).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("'..'") || msg.contains("absolute"),
            "discover_workspace must refuse parent-dir glob: {msg}"
        );
    }

    /// a workspace member that declares its own `catalogs` field
    /// in its package.json must not crash discovery — but the resolver
    /// only honours root-level catalogs, so the silent-drop posture is
    /// surfaced via a `tracing::warn` from `warn_on_member_catalogs`
    /// at discovery time. The structural assertion here is that
    /// discovery still succeeds (the warn path doesn't panic and the
    /// member is still loaded). The visibility leg of the fix is the
    /// warn itself, which is exercised in operator logs.
    #[test]
    fn discover_workspace_admits_member_with_unused_catalogs_field() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "root-with-member-catalog",
                "workspaces": ["packages/*"]
            }"#,
        );
        let member_dir = dir.path().join("packages/widget");
        std::fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{
                "name": "widget",
                "version": "1.0.0",
                "catalogs": {
                    "default": { "react": "^18.0.0" }
                }
            }"#,
        );
        let ws = discover_workspace(dir.path())
            .expect("discovery must not fail when a member has catalogs")
            .expect("workspace must still be discovered");
        assert_eq!(ws.members.len(), 1);
        assert_eq!(ws.members[0].package.name.as_deref(), Some("widget"));
        assert_eq!(
            ws.members[0].package.catalogs.len(),
            1,
            "the member's catalogs field is still loaded into the struct (the warn surfaces the ignored-by-resolver posture, it does not strip the data)"
        );
    }

    #[test]
    fn discover_workspace_reads_default_and_named_catalogs_from_pnpm_workspace_yaml() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "root-with-pnpm-catalogs"
            }"#,
        );
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            r#"packages:
  - "packages/*"
catalog:
  react: ^18.2.0
catalogs:
  testing:
    vitest: ^1.0.0
"#,
        )
        .unwrap();
        let member_dir = dir.path().join("packages/app");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{
                "name": "app",
                "version": "1.0.0"
            }"#,
        );

        let ws = discover_workspace(dir.path())
            .expect("discovery must read pnpm-workspace.yaml")
            .expect("pnpm-workspace.yaml packages should create a workspace");

        assert_eq!(
            ws.root_package.catalogs["default"]["react"], "^18.2.0",
            "pnpm-workspace.yaml catalog should become the default catalog"
        );
        assert_eq!(
            ws.root_package.catalogs["testing"]["vitest"], "^1.0.0",
            "pnpm-workspace.yaml catalogs should become named catalogs"
        );
    }

    #[test]
    fn discover_workspace_reads_cleanup_unused_catalogs_from_pnpm_workspace_yaml() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "root-with-pnpm-cleanup"
            }"#,
        );
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            r#"packages:
  - "packages/*"
cleanupUnusedCatalogs: true
"#,
        )
        .unwrap();
        let member_dir = dir.path().join("packages/app");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{
                "name": "app",
                "version": "1.0.0"
            }"#,
        );

        let ws = discover_workspace(dir.path())
            .expect("discovery must read pnpm cleanup config")
            .expect("pnpm-workspace.yaml packages should create a workspace");

        assert_eq!(
            ws.root_package
                .lpm
                .as_ref()
                .and_then(|lpm| lpm.cleanup_unused_catalogs),
            Some(true),
            "pnpm-workspace.yaml cleanupUnusedCatalogs should feed root lpm config"
        );
    }

    #[test]
    fn package_json_cleanup_unused_catalogs_overrides_pnpm_workspace_yaml() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "root-with-cleanup-precedence",
                "workspaces": ["packages/*"],
                "lpm": {
                    "cleanupUnusedCatalogs": false
                }
            }"#,
        );
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            r#"packages:
  - "packages/*"
cleanupUnusedCatalogs: true
"#,
        )
        .unwrap();
        let member_dir = dir.path().join("packages/app");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{
                "name": "app",
                "version": "1.0.0"
            }"#,
        );

        let ws = discover_workspace(dir.path())
            .expect("discovery must read pnpm cleanup config")
            .expect("workspace must be discovered");

        assert_eq!(
            ws.root_package
                .lpm
                .as_ref()
                .and_then(|lpm| lpm.cleanup_unused_catalogs),
            Some(false),
            "package.json lpm.cleanupUnusedCatalogs should win over pnpm-workspace.yaml"
        );
    }

    #[test]
    fn package_json_catalogs_override_pnpm_workspace_yaml_catalogs() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "root-with-catalog-precedence",
                "workspaces": ["packages/*"],
                "catalogs": {
                    "default": {
                        "react": "^19.0.0"
                    }
                }
            }"#,
        );
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            r#"packages:
  - "packages/*"
catalog:
  react: ^18.2.0
  react-dom: ^18.2.0
"#,
        )
        .unwrap();
        let member_dir = dir.path().join("packages/app");
        fs::create_dir_all(&member_dir).unwrap();
        create_package_json(
            &member_dir,
            r#"{
                "name": "app",
                "version": "1.0.0"
            }"#,
        );

        let ws = discover_workspace(dir.path())
            .expect("discovery must merge pnpm-workspace.yaml catalogs")
            .expect("workspace must be discovered");

        assert_eq!(
            ws.root_package.catalogs["default"]["react"], "^19.0.0",
            "package.json should win when both files define the same catalog entry"
        );
        assert_eq!(
            ws.root_package.catalogs["default"]["react-dom"], "^18.2.0",
            "non-conflicting pnpm-workspace.yaml catalog entries should still be imported"
        );
    }

    #[test]
    fn discover_workspace_from_nested_member_uses_nearest_workspace_root_catalog() {
        let dir = tempfile::tempdir().unwrap();
        create_package_json(
            dir.path(),
            r#"{
                "name": "outer-workspace"
            }"#,
        );
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            r#"packages:
  - "packages/*"
catalog:
  is-positive: ^1.0.0
"#,
        )
        .unwrap();

        let inner_root = dir.path().join("packages/app");
        fs::create_dir_all(&inner_root).unwrap();
        create_package_json(
            &inner_root,
            r#"{
                "name": "inner-workspace"
            }"#,
        );
        fs::write(
            inner_root.join("pnpm-workspace.yaml"),
            r#"packages:
  - "packages/*"
catalog:
  is-positive: ^2.0.0
"#,
        )
        .unwrap();

        let leaf_dir = inner_root.join("packages/leaf");
        fs::create_dir_all(&leaf_dir).unwrap();
        create_package_json(
            &leaf_dir,
            r#"{
                "name": "leaf"
            }"#,
        );

        let ws = discover_workspace(&leaf_dir)
            .expect("nested workspace discovery must succeed")
            .expect("nested member must resolve to its nearest workspace root");

        assert_eq!(ws.root, inner_root);
        assert_eq!(ws.root_package.catalogs["default"]["is-positive"], "^2.0.0");
        assert_eq!(ws.members.len(), 1);
        assert_eq!(ws.members[0].package.name.as_deref(), Some("leaf"));
    }
}
