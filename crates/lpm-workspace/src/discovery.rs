use serde::Deserialize;
use std::collections::HashMap;
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
        let pkg_json_path = current.join("package.json");
        match read_package_json(&pkg_json_path) {
            Ok(mut root_package) => {
                // Check for workspace globs in package.json
                let workspace_globs = match &root_package.workspaces {
                    Some(WorkspacesConfig::Globs(globs)) => Some(globs.clone()),
                    Some(WorkspacesConfig::Object { packages }) => Some(packages.clone()),
                    None => None,
                };

                // Also check for pnpm-workspace.yaml
                let pnpm_workspace_path = current.join("pnpm-workspace.yaml");
                let pnpm_workspace = read_pnpm_workspace(&pnpm_workspace_path)?;

                if let Some(config) = pnpm_workspace.as_ref() {
                    merge_pnpm_workspace_config(&mut root_package, config);
                }

                let globs = workspace_globs.or_else(|| {
                    pnpm_workspace.as_ref().and_then(|config| {
                        if config.packages.is_empty() {
                            None
                        } else {
                            Some(config.packages.clone())
                        }
                    })
                });

                if let Some(globs) = globs {
                    let members = discover_members(&current, &globs)?;
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
/// only place to refuse this — the glob library happily walks
/// anywhere the OS lets it.
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
    let mut members = Vec::new();
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    for pattern in globs {
        // refuse path-escape shapes at the manifest boundary.
        validate_workspace_glob(pattern)?;

        // Resolve glob pattern relative to workspace root
        let full_pattern = root.join(pattern).join("package.json");
        let pattern_str = full_pattern.to_string_lossy().to_string();

        let paths = glob::glob(&pattern_str)
            .map_err(|e| WorkspaceError::Parse(format!("invalid glob pattern '{pattern}': {e}")))?;

        for entry in paths {
            let pkg_json_path =
                entry.map_err(|e| WorkspaceError::Io(format!("glob error: {e}")))?;

            // Defence-in-depth: even with the pattern validated
            // above, refuse any match whose canonical resolution
            // doesn't sit under the canonical project root. Catches
            // a glob match that traverses an existing symlink out
            // of the tree.
            let canonical_match = pkg_json_path
                .canonicalize()
                .unwrap_or_else(|_| pkg_json_path.clone());
            if !canonical_match.starts_with(&canonical_root) {
                tracing::warn!(
                    pattern = %pattern,
                    matched = %pkg_json_path.display(),
                    canonical = %canonical_match.display(),
                    canonical_root = %canonical_root.display(),
                    "skipping workspace member outside project root"
                );
                continue;
            }

            let member_dir = pkg_json_path.parent().unwrap().to_path_buf();
            let package = read_package_json(&pkg_json_path)?;

            members.push(WorkspaceMember {
                path: member_dir,
                package,
            });
        }
    }

    // Sort by path for deterministic ordering
    members.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(members)
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
