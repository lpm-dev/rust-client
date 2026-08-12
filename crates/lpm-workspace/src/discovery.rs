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
