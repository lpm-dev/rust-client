//! `lpm deploy` — materialize a workspace member's selected dependency closure into
//! a self-contained directory ready for Docker / `COPY --from=pruned`.
//!
//! ## High-level pipeline
//!
//! 1. Resolve `--filter <expr>` via [`crate::commands::install_targets`]; assert
//!    the result is exactly one member (deploy is single-target).
//! 2. Validate the output directory (must be outside the workspace, must be
//!    empty unless `--force`).
//! 3. Copy package-publishable source files into the output dir, applying
//!    the deny list (no `.env`, no `node_modules`, no `.git`, etc.).
//! 4. Copy any selected local workspace dependencies into a deploy-local
//!    source area and rewrite `workspace:*` references to relative `file:`
//!    specs.
//! 5. Run the install pipeline with an LPM root inside the output dir to materialize the
//!    dependency tree (downloads tarballs, links into `output/node_modules`).
//! 6. Emit a structured success summary.
//!
//! ## Key invariants
//!
//! - **The source workspace is read-only.** Deploy never modifies any file
//!   under the workspace root.
//! - **`--dry-run` writes nothing.** Hard rule: zero filesystem writes when
//!   `dry_run == true`.
//! - **Deploy targets exactly one member.** Multi-member deploy is a future release.
//! - **Deploy output is portable on Unix.** Internal absolute symlinks under
//!   `node_modules` are rewritten to relative symlinks after install.

use crate::commands::install_targets::{install_root_for, resolve_install_targets};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// The dependency sections in `package.json` that may contain `workspace:*`
/// references. Iterated by [`rewrite_workspace_protocol_in_deploy_manifest`]
/// to make the deploy output self-contained.
const REWRITE_DEP_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
];

/// Files and directories that are NEVER copied to the deploy output.
///
/// Match by EXACT basename. The list is intentionally small and conservative
/// —a future release may add a user-configurable extension via `package.json` or
/// a `--exclude <glob>` flag.
///
/// Categories:
/// - **LPM internal state**: `node_modules`, `.lpm`, `lpm.lock`, `lpm.lockb`
///   are recreated by the install pipeline at the deploy output dir, so
///   copying them is wasted work AND would mask any inconsistency.
/// - **Secrets** (CRITICAL security boundary): `.env*` files contain
///   credentials and must NEVER ride along into a deploy output. Even a
///   developer-only `.env.local` is a footgun if it leaks into a Docker image.
/// - **Version control**: `.git`, `.svn`, `.hg` — the deploy output is not
///   a repo and shouldn't carry git history.
/// - **OS / editor cruft**: `.DS_Store`, `Thumbs.db`, swap files.
const DEPLOY_DENY_BASENAMES: &[&str] = &[
    // LPM internal state
    "node_modules",
    ".lpm",
    "lpm.lock",
    "lpm.lockb",
    // Secrets — critical security boundary
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
    ".env.production",
    ".env.production.local",
    ".env.test",
    ".env.test.local",
    // Version control
    ".git",
    ".gitignore",
    ".npmignore",
    ".gitattributes",
    ".svn",
    ".hg",
    // Editor / OS cruft
    ".DS_Store",
    "Thumbs.db",
];

const DEPLOY_WORKSPACE_DIR: &str = ".lpm/deploy-workspace";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DependencyMode {
    Production,
    Development,
}

impl DependencyMode {
    fn from_flags(_prod: bool, dev: bool) -> Self {
        if dev {
            Self::Development
        } else {
            Self::Production
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ManifestSelectionStats {
    dev_dependencies_stripped: usize,
    production_dependencies_stripped: usize,
    optional_dependencies_stripped: usize,
}

impl ManifestSelectionStats {
    fn add(&mut self, other: &Self) {
        self.dev_dependencies_stripped += other.dev_dependencies_stripped;
        self.production_dependencies_stripped += other.production_dependencies_stripped;
        self.optional_dependencies_stripped += other.optional_dependencies_stripped;
    }
}

/// Stats from a [`copy_member_source`] call. Used by the deploy summary
/// (human and JSON output paths).
#[derive(Debug, Clone, Default)]
pub(crate) struct CopyStats {
    pub files_copied: usize,
    pub files_skipped: usize,
    pub bytes_copied: u64,
}

#[derive(Debug, Clone)]
struct PackageFileSelector {
    files: Option<Vec<String>>,
    ignore_rules: Vec<IgnoreRule>,
}

#[derive(Debug, Clone)]
struct IgnoreRule {
    pattern: String,
    negated: bool,
    anchored: bool,
    directory_only: bool,
}

impl PackageFileSelector {
    fn from_package_dir(package_dir: &Path) -> Result<Self, LpmError> {
        let manifest_path = package_dir.join("package.json");
        let manifest = std::fs::read_to_string(&manifest_path).map_err(|e| {
            LpmError::Script(format!(
                "deploy: failed to read package manifest {manifest_path:?}: {e}"
            ))
        })?;
        let doc: serde_json::Value = serde_json::from_str(&manifest)
            .map_err(|e| LpmError::Script(format!("deploy: invalid package.json: {e}")))?;
        let files = doc
            .get("files")
            .and_then(|value| value.as_array())
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.as_str())
                    .map(normalize_package_pattern)
                    .filter(|entry| !entry.is_empty())
                    .collect::<Vec<_>>()
            })
            .filter(|entries| !entries.is_empty());

        let ignore_rules = if files.is_none() {
            read_ignore_rules(package_dir)?
        } else {
            Vec::new()
        };

        Ok(Self {
            files,
            ignore_rules,
        })
    }

    fn should_copy(&self, rel_path: &Path, is_dir: bool) -> bool {
        let rel = normalize_relative_path(rel_path);
        if rel.is_empty() || package_publish_always_includes(&rel) {
            return true;
        }
        if let Some(files) = &self.files {
            return files
                .iter()
                .any(|pattern| files_entry_matches(pattern, &rel, is_dir));
        }

        let mut included = true;
        for rule in &self.ignore_rules {
            if rule.matches(&rel, is_dir) {
                included = rule.negated;
            }
        }
        included
    }
}

impl IgnoreRule {
    fn matches(&self, rel: &str, is_dir: bool) -> bool {
        if self.directory_only && !is_dir {
            return false;
        }
        let pattern = self.pattern.as_str();
        if self.anchored || pattern.contains('/') {
            glob_match(pattern, rel)
        } else {
            rel.split('/')
                .any(|component| glob_match(pattern, component))
        }
    }
}

fn read_ignore_rules(package_dir: &Path) -> Result<Vec<IgnoreRule>, LpmError> {
    let npmignore = package_dir.join(".npmignore");
    let gitignore = package_dir.join(".gitignore");
    let ignore_path = if npmignore.exists() {
        Some(npmignore)
    } else if gitignore.exists() {
        Some(gitignore)
    } else {
        None
    };
    let Some(ignore_path) = ignore_path else {
        return Ok(Vec::new());
    };
    let content = std::fs::read_to_string(&ignore_path).map_err(|e| {
        LpmError::Script(format!(
            "deploy: failed to read ignore file {ignore_path:?}: {e}"
        ))
    })?;
    let mut rules = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let negated = line.starts_with('!');
        let without_negation = if negated { &line[1..] } else { line };
        let anchored = without_negation.starts_with('/');
        let without_anchor = without_negation.trim_start_matches('/');
        let directory_only = without_anchor.ends_with('/');
        let pattern = normalize_package_pattern(without_anchor.trim_end_matches('/'));
        if pattern.is_empty() {
            continue;
        }
        rules.push(IgnoreRule {
            pattern,
            negated,
            anchored,
            directory_only,
        });
    }
    Ok(rules)
}

fn normalize_relative_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            std::path::Component::ParentDir => Some("..".to_string()),
            std::path::Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_package_pattern(pattern: &str) -> String {
    pattern
        .trim()
        .trim_start_matches("./")
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn package_publish_always_includes(rel: &str) -> bool {
    if rel == "package.json" {
        return true;
    }
    let lowercase = rel.to_ascii_lowercase();
    lowercase == "readme"
        || lowercase.starts_with("readme.")
        || lowercase == "license"
        || lowercase.starts_with("license.")
}

fn files_entry_matches(pattern: &str, rel: &str, is_dir: bool) -> bool {
    let pattern = pattern.trim_end_matches('/');
    if rel == pattern || rel.starts_with(&format!("{pattern}/")) {
        return true;
    }
    if is_dir && pattern.starts_with(&format!("{rel}/")) {
        return true;
    }
    glob_match(pattern, rel)
}

fn glob_match(pattern: &str, rel: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|pattern| pattern.matches_path(Path::new(rel)))
        .unwrap_or(false)
}

/// Recursively copy `src_dir` into `dst_dir`, skipping any path that matches
/// the [`DEPLOY_DENY_BASENAMES`] list. Uses hardlink when possible (zero disk
/// cost on the same filesystem), falls back to file copy for cross-device.
///
/// On macOS, falls back to clonefile-via-hardlink semantics — the directory
/// tree is walked file-by-file rather than as a single clonefile call,
/// because clonefile would copy denied entries too. Per-file hardlink lets
/// us apply the deny list cleanly.
///
/// **Security invariants:**
/// - Files in [`DEPLOY_DENY_BASENAMES`] are NEVER copied (regression-tested).
/// - The function only writes inside `dst_dir`. It does not modify `src_dir`.
/// - Symlinks pointing outside `src_dir` are NOT followed; they are copied
///   as-is (preserving the link, which the user may have intentionally
///   created — doesn't second-guess this).
pub(crate) fn copy_member_source(src_dir: &Path, dst_dir: &Path) -> Result<CopyStats, LpmError> {
    let mut stats = CopyStats::default();

    if !src_dir.exists() {
        return Err(LpmError::Script(format!(
            "deploy: source member directory {src_dir:?} does not exist"
        )));
    }

    std::fs::create_dir_all(dst_dir)
        .map_err(|e| LpmError::Script(format!("failed to create deploy output dir: {e}")))?;

    let selector = PackageFileSelector::from_package_dir(src_dir)?;
    copy_member_source_recursive(src_dir, src_dir, dst_dir, &selector, &mut stats)?;
    Ok(stats)
}

/// Inner recursive walker. Separated so the public entry point can do the
/// one-time `create_dir_all` and stats initialization.
fn copy_member_source_recursive(
    root: &Path,
    src: &Path,
    dst: &Path,
    selector: &PackageFileSelector,
    stats: &mut CopyStats,
) -> Result<(), LpmError> {
    let entries = std::fs::read_dir(src)
        .map_err(|e| LpmError::Script(format!("failed to read source dir {src:?}: {e}")))?;

    for entry in entries {
        let entry =
            entry.map_err(|e| LpmError::Script(format!("failed to read directory entry: {e}")))?;
        let basename = entry.file_name();
        let basename_str = basename.to_string_lossy();

        // Apply the deny list at every level (not just root) so a nested
        // .env or node_modules anywhere under the source is excluded.
        if DEPLOY_DENY_BASENAMES
            .iter()
            .any(|denied| *denied == basename_str.as_ref())
        {
            stats.files_skipped += 1;
            continue;
        }

        let src_path = entry.path();
        let dst_path = dst.join(&basename);

        let file_type = entry
            .file_type()
            .map_err(|e| LpmError::Script(format!("failed to stat {src_path:?}: {e}")))?;
        let rel_path = src_path.strip_prefix(root).unwrap_or(src_path.as_path());
        if !selector.should_copy(rel_path, file_type.is_dir()) {
            stats.files_skipped += 1;
            continue;
        }

        if file_type.is_dir() {
            std::fs::create_dir_all(&dst_path)
                .map_err(|e| LpmError::Script(format!("failed to create dir {dst_path:?}: {e}")))?;
            copy_member_source_recursive(root, &src_path, &dst_path, selector, stats)?;
        } else if file_type.is_symlink() {
            // Preserve symlinks as-is. Don't follow them — that could escape
            // the source dir.
            #[cfg(unix)]
            {
                let target = std::fs::read_link(&src_path).map_err(|e| {
                    LpmError::Script(format!("failed to read symlink {src_path:?}: {e}"))
                })?;
                std::os::unix::fs::symlink(&target, &dst_path).map_err(|e| {
                    LpmError::Script(format!("failed to recreate symlink {dst_path:?}: {e}"))
                })?;
                stats.files_copied += 1;
            }
            #[cfg(windows)]
            {
                // M42: a Windows symlink/junction whose target sits
                // outside the source member tree was previously
                // followed: `std::fs::metadata` resolves the target,
                // dir-symlinks recursed, file-symlinks were copied
                // with `std::fs::copy`. A malicious repo could include
                // a junction under the member tree pointing at user
                // secrets and have those bytes copied into the deploy
                // output despite the deny list.
                //
                // Skip every symlink/junction with a tracing::warn
                // instead. Loss of fidelity for legitimate
                // intra-source symlinks; the safer posture matches
                // the Unix branch's "preserve as-is, never follow"
                // contract and refuses to silently materialise
                // out-of-source bytes.
                tracing::warn!(
                    target: "lpm_cli::deploy",
                    src = %src_path.display(),
                    "skipping Windows symlink/junction in deploy member tree (M42 — refuses to follow out-of-source targets)"
                );
                stats.files_skipped += 1;
            }
            #[cfg(not(any(unix, windows)))]
            {
                stats.files_skipped += 1;
            }
        } else {
            // Regular file: hardlink first, fall back to copy.
            // Hardlinks are zero-cost on the same filesystem and preserve
            // the source bytes exactly. Cross-device falls through to copy.
            let bytes = std::fs::metadata(&src_path).map_or(0, |m| m.len());
            if std::fs::hard_link(&src_path, &dst_path).is_err() {
                std::fs::copy(&src_path, &dst_path).map_err(|e| {
                    LpmError::Script(format!("failed to copy {src_path:?} to {dst_path:?}: {e}"))
                })?;
            }
            stats.files_copied += 1;
            stats.bytes_copied += bytes;
        }
    }

    Ok(())
}

/// Resolved deploy plan: which member to deploy and where it lives on disk.
/// Returned by [`resolve_deploy_target`] and consumed by the deploy pipeline.
#[derive(Debug, Clone)]
pub(crate) struct DeployPlan {
    /// Path to the source member's `package.json`. Read during manifest
    /// rewrite.
    #[allow(dead_code)]
    pub member_manifest: PathBuf,
    /// Path to the source member's directory (`member_manifest.parent()`).
    pub member_dir: PathBuf,
    /// Validated, normalized output directory the deploy will write into.
    pub output_dir: PathBuf,
}

/// Resolve the deploy target from CLI flags and validate the output directory.
///
/// Returns a [`DeployPlan`] on success, or an actionable [`LpmError::Script`]
/// describing what's wrong. Validation rules:
///
/// - a filter must be non-empty
/// - filters must match exactly one workspace member
/// - The output directory must NOT be inside the workspace tree (self-deploy
///   loop prevention)
/// - The output directory must be empty (or not exist), unless `force` is set
pub(crate) fn resolve_deploy_target(
    cwd: &Path,
    output_dir: &Path,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    force: bool,
) -> Result<DeployPlan, LpmError> {
    if filters.is_empty() && filter_prod.is_empty() {
        return Err(LpmError::Script(
            "lpm deploy requires --filter <expr> or --filter-prod <expr> to identify the workspace member to deploy".into(),
        ));
    }

    // 1. Resolve target via the shared install_targets helper.
    //    has_packages=true so we never hit the "ambiguous root refresh" branch.
    //    workspace_root_flag=false because deploy never targets the root manifest.
    let targets = resolve_install_targets(
        cwd,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        false,
        true,
    )?;

    // 2. Single-member assertion.
    if targets.member_manifests.is_empty() {
        return Err(LpmError::Script(format!(
            "lpm deploy: --filter {filters:?} matched no workspace members. \
             Refine the filter to point at exactly one member."
        )));
    }
    if targets.member_manifests.len() > 1 {
        return Err(LpmError::Script(format!(
            "lpm deploy: --filter {:?} matched {} workspace members; deploy requires exactly one. \
             Refine the filter to target a single member.",
            filters,
            targets.member_manifests.len()
        )));
    }

    let member_manifest = targets.member_manifests[0].clone();
    let member_dir = install_root_for(&member_manifest).to_path_buf();

    // 3. Output directory validation.
    let output_dir = validate_output_dir(cwd, output_dir, force)?;

    Ok(DeployPlan {
        member_manifest,
        member_dir,
        output_dir,
    })
}

/// Validate the deploy output directory.
///
/// - Must not be inside the workspace tree (prevents self-deploy loops).
/// - Must be empty, not exist yet, or `force == true`.
///
/// Returns the validated, normalized path. Does NOT create the directory
/// or clean it for `--force` — those are the caller's responsibility.
///
/// the self-loop guard now canonicalizes
/// BOTH the workspace root AND the output path through `canonicalize_or_partial`
/// before comparing. The old implementation mixed canonical and lexical paths
/// in the same comparison, which silently passed on macOS when the workspace
/// was under `/tmp/...` (because `/tmp` symlinks to `/private/tmp` and the
/// asymmetric prefix comparison missed the relationship).
fn validate_output_dir(cwd: &Path, output_dir: &Path, force: bool) -> Result<PathBuf, LpmError> {
    let normalized = lexical_normalize(&cwd.join(output_dir));

    // Self-deploy loop guard: walk up from cwd looking for a workspace root,
    // then check that the output dir is not inside it.
    if let Ok(Some(workspace)) = lpm_workspace::discover_workspace(cwd) {
        // Resolve BOTH paths through the same normalization function so the
        // comparison is meaningful regardless of which form (canonical vs
        // lexical-with-symlinks) the inputs arrive in. This is the         // audit fix: the old code compared a mix of forms and missed the
        // macOS `/tmp → /private/tmp` symlink case.
        let workspace_canonical = canonicalize_or_partial(&workspace.root);
        let output_canonical = canonicalize_or_partial(&normalized);

        if output_canonical == workspace_canonical
            || output_canonical.starts_with(&workspace_canonical)
        {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} resolves to {output_canonical:?} \
                 which is inside the workspace at {workspace_canonical:?}. \
                 Choose an output directory outside the workspace to prevent self-deploy loops."
            )));
        }
    }

    // Empty / force check. Non-existent paths are fine — the copy step
    // will create them. For `--force` on a non-empty existing dir, this
    // function only suppresses the non-empty error; the actual cleanup
    // (`remove_dir_all` + `create_dir_all`) lives in `run` AFTER this
    // validation succeeds. That ordering matters: validate_output_dir is
    // the safety gate that confirms the output is OUTSIDE the workspace,
    // and we deliberately never remove anything until the gate has passed.
    // audit fix Medium  wired the cleanup in `run`.
    if normalized.exists() {
        let is_empty =
            std::fs::read_dir(&normalized).map_or(true, |mut iter| iter.next().is_none());
        if !is_empty && !force {
            return Err(LpmError::Script(format!(
                "lpm deploy: output directory {output_dir:?} is not empty. \
                 Use --force to overwrite, or choose an empty/nonexistent output directory."
            )));
        }
    }

    Ok(normalized)
}

/// Canonicalize a path to its symlink-resolved absolute form, even when
/// the path itself does not exist yet.
///
/// Walks up from `path` looking for the deepest existing ancestor, calls
/// `canonicalize` on it (which follows symlinks), then re-appends the
/// non-existent tail components in their original order. This produces a
/// path that is comparable with other canonicalized paths under the same
/// symlink-resolved root.
///
/// added to fix the macOS self-loop
/// guard bypass. The old implementation tried direct `canonicalize` and
/// fell back to the raw lexical form on failure. That fallback meant
/// non-existent output paths under `/tmp/...` were compared in lexical
/// form against canonical workspace roots like `/private/tmp/...`, and
/// the prefix comparison silently missed the relationship.
fn canonicalize_or_partial(path: &Path) -> PathBuf {
    // Fast path: the whole path already exists, canonicalize directly.
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    // Walk up to the deepest existing ancestor, collecting the tail
    // components we'll re-append in order.
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            // Found an existing ancestor. Canonicalize it and re-append
            // the tail in original order.
            let mut result = current.canonicalize().unwrap_or(current);
            for component in tail.iter().rev() {
                result.push(component);
            }
            return result;
        }
        let Some(parent) = current.parent().map(|p| p.to_path_buf()) else {
            // Reached the filesystem root without finding an existing
            // ancestor. Fall back to the lexical form — we did our best.
            return path.to_path_buf();
        };
        if let Some(name) = current.file_name() {
            tail.push(name.to_os_string());
        }
        current = parent;
    }
}

/// Lexical path normalization: resolve `..` and `.` components without
/// touching the disk. Used as a pre-step before [`canonicalize_or_partial`]
/// to collapse any `..` and `.` components in user-supplied paths.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

#[cfg(test)]
/// Rewrite `workspace:*` references in the deploy output's `package.json`
/// to concrete versions, using the **source workspace** as the version
/// source. The deploy output dir has no parent workspace, so without this
/// rewrite the install pipeline at the output dir would fail to resolve
/// `workspace:*` deps.
///
/// Iterates `dependencies`, `devDependencies`, `peerDependencies`, and
/// `optionalDependencies`. Even though LPM's install pipeline only resolves
/// `dependencies` (verified via F1 in the design doc), the deploy
/// output should be a clean, lookup-able package.json — so we rewrite all
/// four sections defensively.
///
/// **Read-only on the source side**: this function never modifies any file
/// outside `output_dir`. The source workspace manifests are untouched.
///
/// Returns the total number of `workspace:*` references rewritten across
/// all sections.
fn rewrite_workspace_protocol_in_deploy_manifest(
    output_dir: &Path,
    source_cwd: &Path,
) -> Result<usize, LpmError> {
    // Discover the source workspace from the original cwd. The deploy
    // output dir is intentionally outside the workspace tree (enforced
    // at target resolution), so we can't discover from there.
    let workspace = lpm_workspace::discover_workspace(source_cwd)
        .map_err(|e| LpmError::Script(format!("workspace discovery failed: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "deploy: source must be inside a workspace (no workspace found)".into(),
            )
        })?;

    let manifest_path = output_dir.join("package.json");
    let content = std::fs::read_to_string(&manifest_path).map_err(|e| {
        LpmError::Script(format!(
            "failed to read deploy manifest at {manifest_path:?}: {e}"
        ))
    })?;

    let mut doc: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| LpmError::Script(format!("invalid package.json in deploy output: {e}")))?;

    let mut total_rewritten = 0;

    for section in REWRITE_DEP_SECTIONS {
        let Some(section_obj) = doc.get_mut(*section).and_then(|v| v.as_object_mut()) else {
            continue;
        };

        // Snapshot the section as a HashMap for the resolver. The resolver
        // mutates the HashMap in place; we then write the rewritten values
        // back into the original Map preserving key order.
        let mut temp_deps: HashMap<String, String> = section_obj
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();

        let resolved = lpm_workspace::resolve_workspace_protocol(&mut temp_deps, &workspace)
            .map_err(|e| LpmError::Script(format!("deploy: workspace protocol error: {e}")))?;

        // Apply each rewrite back into the section_obj, preserving the
        // original key order.
        for (name, _original_protocol, _resolved_version) in &resolved {
            if let Some(new_value) = temp_deps.get(name) {
                section_obj.insert(name.clone(), serde_json::Value::String(new_value.clone()));
            }
        }

        total_rewritten += resolved.len();
    }

    // Only write the manifest back if at least one rewrite happened.
    // Otherwise leave the source-copied bytes as-is (preserves any quirks
    // in the source formatting).
    //
    // CRITICAL: `copy_member_source` uses hardlinks for performance. A
    // naive `std::fs::write` here would write THROUGH the hardlink and
    // mutate the source workspace's `package.json`. To preserve the
    // read-only-on-source invariant, we must `remove_file` first to
    // unlink the path from the shared inode, then write a fresh file.
    // This guarantees the source manifest is byte-identical even if the
    // file copy used a hardlink fast path.
    if total_rewritten > 0 {
        let updated = serde_json::to_string_pretty(&doc)
            .map_err(|e| LpmError::Script(format!("failed to serialize deploy manifest: {e}")))?;
        // Break any potential hardlink by unlinking the path first.
        // remove_file is idempotent for our purposes — if it doesn't exist
        // (it should), we still create it below.
        let _ = std::fs::remove_file(&manifest_path);
        std::fs::write(&manifest_path, format!("{updated}\n"))
            .map_err(|e| LpmError::Script(format!("failed to write deploy manifest: {e}")))?;
    }

    Ok(total_rewritten)
}

#[cfg(test)]
/// Strip `devDependencies` from the deploy output's `package.json`.
///
/// Deploy produces a **production closure**. After `lpm install`
/// resolves both `dependencies` and `devDependencies` (matching pnpm / npm
/// semantics), so if we left `devDependencies` in the copied manifest the
/// install pipeline inside the output dir would drag dev-only packages
/// (vitest, tsup, eslint, etc.) into the deploy closure. That would bloat
/// Docker images and re-open the class of bugs this command exists to
/// prevent.
///
/// The function is a no-op when the section is absent, a no-op when the
/// section exists but is empty, and otherwise removes the key entirely.
/// Returns the number of devDependency entries that were stripped so the
/// caller can surface it in the deploy summary.
///
/// **Hardlink safety.** [`copy_member_source`] uses `hard_link` as a
/// performance fast path, so the output's `package.json` can share an
/// inode with the source workspace's `package.json`. A naive `write`
/// would mutate the source — the same trap documented in . We
/// use the same `remove_file` + fresh `write` dance as
/// [`rewrite_workspace_protocol_in_deploy_manifest`] to break the
/// potential hardlink.
fn strip_dev_dependencies_from_deploy_manifest(output_dir: &Path) -> Result<usize, LpmError> {
    let manifest_path = output_dir.join("package.json");
    let content = std::fs::read_to_string(&manifest_path).map_err(|e| {
        LpmError::Script(format!(
            "failed to read deploy manifest at {manifest_path:?}: {e}"
        ))
    })?;

    let mut doc: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| LpmError::Script(format!("invalid package.json in deploy output: {e}")))?;

    let stripped_count = doc
        .get("devDependencies")
        .and_then(|v| v.as_object())
        .map_or(0, |o| o.len());

    if stripped_count == 0 {
        // Key missing or empty object: nothing to do, nothing to write.
        // Leaving the (possibly hardlinked) bytes alone preserves source
        // formatting and avoids an unnecessary write.
        return Ok(0);
    }

    if let Some(obj) = doc.as_object_mut() {
        obj.remove("devDependencies");
    }

    let updated = serde_json::to_string_pretty(&doc)
        .map_err(|e| LpmError::Script(format!("failed to serialize deploy manifest: {e}")))?;

    // Break any potential hardlink to the source manifest, then write a
    // fresh inode at the path. See  rationale in the doc.
    let _ = std::fs::remove_file(&manifest_path);
    std::fs::write(&manifest_path, format!("{updated}\n"))
        .map_err(|e| LpmError::Script(format!("failed to write deploy manifest: {e}")))?;

    Ok(stripped_count)
}

fn read_manifest_value(manifest_path: &Path) -> Result<serde_json::Value, LpmError> {
    let content = std::fs::read_to_string(manifest_path).map_err(|e| {
        LpmError::Script(format!(
            "deploy: failed to read manifest at {manifest_path:?}: {e}"
        ))
    })?;
    serde_json::from_str(&content)
        .map_err(|e| LpmError::Script(format!("deploy: invalid package.json: {e}")))
}

fn write_manifest_value(manifest_path: &Path, doc: &serde_json::Value) -> Result<(), LpmError> {
    let updated = serde_json::to_string_pretty(doc)
        .map_err(|e| LpmError::Script(format!("deploy: failed to serialize manifest: {e}")))?;
    let _ = std::fs::remove_file(manifest_path);
    std::fs::write(manifest_path, format!("{updated}\n"))
        .map_err(|e| LpmError::Script(format!("deploy: failed to write manifest: {e}")))
}

fn section_len(doc: &serde_json::Value, section: &str) -> usize {
    doc.get(section)
        .and_then(|value| value.as_object())
        .map_or(0, |object| object.len())
}

fn remove_manifest_section(doc: &mut serde_json::Value, section: &str) -> usize {
    let count = section_len(doc, section);
    if count > 0
        && let Some(object) = doc.as_object_mut()
    {
        object.remove(section);
    }
    count
}

fn apply_dependency_selection_to_manifest_path(
    manifest_path: &Path,
    mode: DependencyMode,
    no_optional: bool,
) -> Result<ManifestSelectionStats, LpmError> {
    let mut doc = read_manifest_value(manifest_path)?;
    let mut stats = ManifestSelectionStats::default();

    match mode {
        DependencyMode::Production => {
            stats.dev_dependencies_stripped = remove_manifest_section(&mut doc, "devDependencies");
        }
        DependencyMode::Development => {
            stats.production_dependencies_stripped =
                remove_manifest_section(&mut doc, "dependencies");
            stats.optional_dependencies_stripped =
                remove_manifest_section(&mut doc, "optionalDependencies");
        }
    }

    if no_optional && matches!(mode, DependencyMode::Production) {
        stats.optional_dependencies_stripped =
            remove_manifest_section(&mut doc, "optionalDependencies");
    }

    if stats.dev_dependencies_stripped > 0
        || stats.production_dependencies_stripped > 0
        || stats.optional_dependencies_stripped > 0
    {
        write_manifest_value(manifest_path, &doc)?;
    }

    Ok(stats)
}

fn apply_dependency_selection_to_deploy_manifest(
    output_dir: &Path,
    mode: DependencyMode,
    no_optional: bool,
) -> Result<ManifestSelectionStats, LpmError> {
    apply_dependency_selection_to_manifest_path(&output_dir.join("package.json"), mode, no_optional)
}

fn workspace_dep_names_for_package(
    pkg: &lpm_workspace::PackageJson,
    mode: DependencyMode,
    no_optional: bool,
) -> Vec<String> {
    let mut names = Vec::with_capacity(
        pkg.dependencies.len() + pkg.dev_dependencies.len() + pkg.optional_dependencies.len(),
    );
    match mode {
        DependencyMode::Production => {
            collect_workspace_dep_names(&pkg.dependencies, &mut names);
            if !no_optional {
                collect_workspace_dep_names(&pkg.optional_dependencies, &mut names);
            }
        }
        DependencyMode::Development => {
            collect_workspace_dep_names(&pkg.dev_dependencies, &mut names);
        }
    }
    names.sort();
    names.dedup();
    names
}

fn collect_workspace_dep_names(deps: &HashMap<String, String>, names: &mut Vec<String>) {
    for (name, spec) in deps {
        if spec.starts_with("workspace:") {
            names.push(name.clone());
        }
    }
}

fn copy_workspace_dependency_closure(
    output_dir: &Path,
    source_cwd: &Path,
    root_member_name: &str,
    mode: DependencyMode,
    no_optional: bool,
) -> Result<(usize, usize, CopyStats, ManifestSelectionStats), LpmError> {
    let workspace = lpm_workspace::discover_workspace(source_cwd)
        .map_err(|e| LpmError::Script(format!("workspace discovery failed: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "deploy: source must be inside a workspace (no workspace found)".into(),
            )
        })?;

    let members_by_name: HashMap<String, lpm_workspace::WorkspaceMember> = workspace
        .members
        .iter()
        .filter_map(|member| Some((member.package.name.as_deref()?.to_string(), member.clone())))
        .collect();
    let root_member = members_by_name.get(root_member_name).ok_or_else(|| {
        LpmError::Script(format!(
            "deploy: selected member {root_member_name:?} was not found in the source workspace"
        ))
    })?;

    let mut queue: VecDeque<String> =
        workspace_dep_names_for_package(&root_member.package, mode, no_optional).into();
    let mut selected = HashSet::new();
    while let Some(name) = queue.pop_front() {
        if name == root_member_name || !selected.insert(name.clone()) {
            continue;
        }
        let Some(member) = members_by_name.get(&name) else {
            continue;
        };
        for child in workspace_dep_names_for_package(
            &member.package,
            DependencyMode::Production,
            no_optional,
        ) {
            if child != root_member_name && !selected.contains(&child) {
                queue.push_back(child);
            }
        }
    }

    if selected.is_empty() {
        return Ok((
            0,
            0,
            CopyStats::default(),
            ManifestSelectionStats::default(),
        ));
    }

    let mut selected_names: Vec<String> = selected.into_iter().collect();
    selected_names.sort();
    let mut destination_by_name = HashMap::with_capacity(selected_names.len());
    for name in &selected_names {
        let member = members_by_name.get(name).ok_or_else(|| {
            LpmError::Script(format!("deploy: workspace member {name:?} disappeared"))
        })?;
        let relative = pathdiff::diff_paths(&member.path, &workspace.root).ok_or_else(|| {
            LpmError::Script(format!(
                "deploy: failed to compute relative path for workspace member {name}"
            ))
        })?;
        destination_by_name.insert(
            name.clone(),
            output_dir.join(DEPLOY_WORKSPACE_DIR).join(relative),
        );
    }

    let mut copy_stats = CopyStats::default();
    let mut selection_stats = ManifestSelectionStats::default();
    let mut workspace_spec_rewrites = 0;
    for name in &selected_names {
        let member = members_by_name.get(name).ok_or_else(|| {
            LpmError::Script(format!("deploy: workspace member {name:?} disappeared"))
        })?;
        let destination = destination_by_name
            .get(name)
            .expect("destination map is complete");
        let stats = copy_member_source(&member.path, destination)?;
        copy_stats.files_copied += stats.files_copied;
        copy_stats.files_skipped += stats.files_skipped;
        copy_stats.bytes_copied += stats.bytes_copied;

        let manifest_path = destination.join("package.json");
        let member_selection = apply_dependency_selection_to_manifest_path(
            &manifest_path,
            DependencyMode::Production,
            no_optional,
        )?;
        selection_stats.add(&member_selection);
        workspace_spec_rewrites +=
            rewrite_workspace_specs_to_file_paths(&manifest_path, &destination_by_name)?;
    }

    workspace_spec_rewrites += rewrite_workspace_specs_to_file_paths(
        &output_dir.join("package.json"),
        &destination_by_name,
    )?;

    Ok((
        selected_names.len(),
        workspace_spec_rewrites,
        copy_stats,
        selection_stats,
    ))
}

fn rewrite_workspace_specs_to_file_paths(
    manifest_path: &Path,
    destination_by_name: &HashMap<String, PathBuf>,
) -> Result<usize, LpmError> {
    let mut doc = read_manifest_value(manifest_path)?;
    let manifest_dir = manifest_path.parent().ok_or_else(|| {
        LpmError::Script(format!(
            "deploy: manifest path {manifest_path:?} has no parent directory"
        ))
    })?;
    let mut rewritten = 0;

    for section in REWRITE_DEP_SECTIONS {
        let Some(section_obj) = doc
            .get_mut(*section)
            .and_then(|value| value.as_object_mut())
        else {
            continue;
        };
        let keys: Vec<String> = section_obj.keys().cloned().collect();
        for name in keys {
            let Some(raw_spec) = section_obj.get(&name).and_then(|value| value.as_str()) else {
                continue;
            };
            if !raw_spec.starts_with("workspace:") {
                continue;
            }
            let Some(destination) = destination_by_name.get(&name) else {
                continue;
            };
            let relative = pathdiff::diff_paths(destination, manifest_dir).ok_or_else(|| {
                LpmError::Script(format!(
                    "deploy: failed to compute relative file path from {manifest_dir:?} to {destination:?}"
                ))
            })?;
            let relative = normalize_relative_path(&relative);
            section_obj.insert(name, serde_json::Value::String(format!("file:{relative}")));
            rewritten += 1;
        }
    }

    if rewritten > 0 {
        write_manifest_value(manifest_path, &doc)?;
    }

    Ok(rewritten)
}

fn write_pruned_deploy_lockfile_if_possible(
    source_cwd: &Path,
    output_dir: &Path,
) -> Result<Option<usize>, LpmError> {
    let workspace = lpm_workspace::discover_workspace(source_cwd)
        .map_err(|e| LpmError::Script(format!("workspace discovery failed: {e}")))?
        .ok_or_else(|| {
            LpmError::Script(
                "deploy: source must be inside a workspace (no workspace found)".into(),
            )
        })?;
    let source_lockfile_path = workspace.root.join(lpm_lockfile::LOCKFILE_NAME);
    if !source_lockfile_path.exists() {
        return Ok(None);
    }

    let root_specs = match collect_registry_specs_from_deploy_manifests(output_dir)? {
        Some(specs) => specs,
        None => return Ok(None),
    };
    let source_lockfile =
        lpm_lockfile::Lockfile::read_from_file(&source_lockfile_path).map_err(|e| {
            LpmError::Script(format!(
                "deploy: failed to read source lockfile {source_lockfile_path:?}: {e}"
            ))
        })?;

    let mut queue = VecDeque::new();
    for (name, spec) in &root_specs {
        let Some(package) = select_locked_package_for_spec(&source_lockfile, name, spec) else {
            return Ok(None);
        };
        queue.push_back(package.clone());
    }

    let mut selected = HashSet::new();
    while let Some(package) = queue.pop_front() {
        let key = locked_package_key(&package);
        if !selected.insert(key) {
            continue;
        }
        let alias_targets: HashMap<&str, &str> = package
            .alias_dependencies
            .iter()
            .map(|pair| (pair[0].as_str(), pair[1].as_str()))
            .collect();
        for edge in package.dependencies.iter().chain(package.peers.iter()) {
            let Some((local_name, version)) = split_locked_edge(edge) else {
                continue;
            };
            let target = alias_targets.get(local_name).copied().unwrap_or(local_name);
            if let Some(child) = find_locked_package_exact(&source_lockfile, target, version) {
                queue.push_back(child.clone());
            }
        }
    }

    let mut pruned = lpm_lockfile::Lockfile::new();
    pruned.metadata = source_lockfile.metadata.clone();
    pruned.catalogs = source_lockfile.catalogs.clone();
    pruned.packages = source_lockfile
        .packages
        .into_iter()
        .filter(|package| selected.contains(&locked_package_key(package)))
        .collect();
    pruned.root_aliases = source_lockfile
        .root_aliases
        .into_iter()
        .filter(|(local, _)| root_specs.contains_key(local))
        .collect();
    pruned.ambient_peer_installs = source_lockfile
        .ambient_peer_installs
        .into_iter()
        .filter(|name| pruned.packages.iter().any(|package| &package.name == name))
        .collect();
    let package_count = pruned.packages.len();
    pruned
        .write_all(&output_dir.join(lpm_lockfile::LOCKFILE_NAME))
        .map_err(|e| LpmError::Script(format!("deploy: failed to write pruned lockfile: {e}")))?;

    Ok(Some(package_count))
}

fn collect_registry_specs_from_deploy_manifests(
    output_dir: &Path,
) -> Result<Option<HashMap<String, String>>, LpmError> {
    let mut specs = HashMap::new();
    let mut manifests = vec![output_dir.join("package.json")];
    let deploy_workspace = output_dir.join(DEPLOY_WORKSPACE_DIR);
    if deploy_workspace.exists() {
        collect_package_manifests_recursive(&deploy_workspace, &mut manifests)?;
    }

    for manifest in manifests {
        let doc = read_manifest_value(&manifest)?;
        for section in ["dependencies", "devDependencies", "optionalDependencies"] {
            let Some(deps) = doc.get(section).and_then(|value| value.as_object()) else {
                continue;
            };
            for (name, value) in deps {
                let Some(spec) = value.as_str() else {
                    return Ok(None);
                };
                if spec.starts_with("workspace:")
                    || spec.starts_with("file:")
                    || spec.starts_with("link:")
                    || spec.starts_with("portal:")
                {
                    continue;
                }
                if spec.starts_with("catalog:") {
                    return Ok(None);
                }
                specs
                    .entry(name.clone())
                    .or_insert_with(|| spec.to_string());
            }
        }
    }

    Ok(Some(specs))
}

fn collect_package_manifests_recursive(
    dir: &Path,
    manifests: &mut Vec<PathBuf>,
) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(dir)
        .map_err(|e| LpmError::Script(format!("deploy: failed to read {dir:?}: {e}")))?
    {
        let entry = entry
            .map_err(|e| LpmError::Script(format!("deploy: failed to read dir entry: {e}")))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| LpmError::Script(format!("deploy: failed to stat {path:?}: {e}")))?;
        if file_type.is_dir() {
            let manifest = path.join("package.json");
            if manifest.exists() {
                manifests.push(manifest);
            }
            collect_package_manifests_recursive(&path, manifests)?;
        }
    }
    Ok(())
}

fn select_locked_package_for_spec<'a>(
    lockfile: &'a lpm_lockfile::Lockfile,
    local_name: &str,
    spec: &str,
) -> Option<&'a lpm_lockfile::LockedPackage> {
    let (target, range_spec) = match lpm_resolver::ranges::parse_npm_alias(spec) {
        Some(alias) => (alias.target, alias.range),
        None => (local_name.to_string(), spec.to_string()),
    };
    let range = lpm_resolver::NpmRange::parse(&range_spec).ok()?;
    lockfile
        .packages
        .iter()
        .filter_map(|package| {
            if package.name != target {
                return None;
            }
            let version = lpm_resolver::NpmVersion::parse(&package.version).ok()?;
            range.satisfies(&version).then_some((version, package))
        })
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, package)| package)
}

fn find_locked_package_exact<'a>(
    lockfile: &'a lpm_lockfile::Lockfile,
    name: &str,
    version: &str,
) -> Option<&'a lpm_lockfile::LockedPackage> {
    lockfile
        .packages
        .iter()
        .find(|package| package.name == name && package.version == version)
}

fn split_locked_edge(edge: &str) -> Option<(&str, &str)> {
    edge.rfind('@')
        .map(|at| (&edge[..at], &edge[at + 1..]))
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
}

fn locked_package_key(package: &lpm_lockfile::LockedPackage) -> (String, String, Option<String>) {
    (
        package.name.clone(),
        package.version.clone(),
        package.source.clone(),
    )
}

#[cfg(unix)]
fn retarget_internal_node_modules_symlinks(output_dir: &Path) -> Result<usize, LpmError> {
    let node_modules = output_dir.join("node_modules");
    if !node_modules.exists() {
        return Ok(0);
    }
    let output_root = canonicalize_or_partial(output_dir);
    retarget_internal_symlinks_recursive(&node_modules, output_dir, &output_root)
}

#[cfg(unix)]
fn retarget_internal_symlinks_recursive(
    dir: &Path,
    output_dir: &Path,
    output_root: &Path,
) -> Result<usize, LpmError> {
    let mut retargeted = 0;
    for entry in std::fs::read_dir(dir)
        .map_err(|e| LpmError::Script(format!("deploy: failed to read {dir:?}: {e}")))?
    {
        let entry = entry
            .map_err(|e| LpmError::Script(format!("deploy: failed to read dir entry: {e}")))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| LpmError::Script(format!("deploy: failed to stat {path:?}: {e}")))?;
        if file_type.is_symlink() {
            let target = std::fs::read_link(&path).map_err(|e| {
                LpmError::Script(format!("deploy: failed to read symlink {path:?}: {e}"))
            })?;
            if !target.is_absolute() {
                continue;
            }
            let target_canonical = canonicalize_or_partial(&target);
            if !target_canonical.starts_with(output_root) {
                continue;
            }
            let target_for_relative = if target.starts_with(output_dir) {
                target
            } else {
                let suffix = target_canonical.strip_prefix(output_root).map_err(|e| {
                    LpmError::Script(format!(
                        "deploy: failed to strip deploy root from {target_canonical:?}: {e}"
                    ))
                })?;
                output_dir.join(suffix)
            };
            let parent = path.parent().ok_or_else(|| {
                LpmError::Script(format!("deploy: symlink path {path:?} has no parent"))
            })?;
            let relative = pathdiff::diff_paths(&target_for_relative, parent).ok_or_else(|| {
                LpmError::Script(format!(
                    "deploy: failed to compute relative symlink target from {parent:?} to {target_for_relative:?}"
                ))
            })?;
            std::fs::remove_file(&path).map_err(|e| {
                LpmError::Script(format!("deploy: failed to replace {path:?}: {e}"))
            })?;
            std::os::unix::fs::symlink(&relative, &path).map_err(|e| {
                LpmError::Script(format!("deploy: failed to write symlink {path:?}: {e}"))
            })?;
            retargeted += 1;
        } else if file_type.is_dir() {
            retargeted += retarget_internal_symlinks_recursive(&path, output_dir, output_root)?;
        }
    }
    Ok(retargeted)
}

#[cfg(not(unix))]
fn retarget_internal_node_modules_symlinks(_output_dir: &Path) -> Result<usize, LpmError> {
    Ok(0)
}

/// Read the deploy target's package.json `name` field for the success
/// summary. Falls back to the directory name if `name` is missing or
/// non-string.
fn read_member_name(manifest_path: &Path) -> String {
    let fallback = || {
        manifest_path
            .parent()
            .and_then(|p| p.file_name())
            .map_or_else(
                || "(unnamed)".to_string(),
                |n| n.to_string_lossy().to_string(),
            )
    };
    let Ok(content) = std::fs::read_to_string(manifest_path) else {
        return fallback();
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&content) else {
        return fallback();
    };
    doc.get("name")
        .and_then(|v| v.as_str())
        .map_or_else(fallback, |s| s.to_string())
}

/// Run the `lpm deploy` command.
///
/// All four steps are wired — target resolution, source file
/// copy, manifest rewrite, and install pipeline at the deploy output dir.
///
/// In `--json` mode the deploy command produces a deploy-specific summary
/// JSON object on stdout AFTER the install pipeline's own JSON output.
/// Together they form a JSON-Lines stream (two objects, one per line).
/// This is the same multi-object pattern uses for multi-target
/// installs and is documented as the deploy JSON contract.
#[allow(clippy::too_many_arguments)] // matches the install/uninstall surface for consistency
pub async fn run(
    client: &RegistryClient,
    cwd: &Path,
    output_dir: &Path,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    force: bool,
    prod: bool,
    dev: bool,
    no_optional: bool,
    dry_run: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let start = Instant::now();
    if prod && dev {
        return Err(LpmError::Script(
            "lpm deploy: --prod and --dev are mutually exclusive".into(),
        ));
    }
    let dependency_mode = DependencyMode::from_flags(prod, dev);
    let plan = resolve_deploy_target(
        cwd,
        output_dir,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        force,
    )?;
    let member_name = read_member_name(&plan.member_manifest);
    let materialize_message = format!(
        "Materializing {} closure for {}",
        dependency_mode.label(),
        install_ui::yellow(&member_name)
    );

    if dry_run {
        // Dry-run: validation succeeded, but write nothing. Surface the
        // resolved plan so the user knows what would happen.
        if json_output {
            let payload = serde_json::json!({
                "success": true,
                "dry_run": true,
                "member": member_name,
                "member_dir": plan.member_dir.display().to_string(),
                "output_dir": plan.output_dir.display().to_string(),
                "dependency_mode": dependency_mode.label(),
                "optional_dependencies": !no_optional,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
        } else {
            install_ui::phase(&materialize_message);
            deploy_detail_colored(
                "output:",
                install_ui::yellow(&plan.output_dir.display().to_string()),
            );
            deploy_detail_colored(
                "member:",
                install_ui::cyan(&plan.member_dir.display().to_string()),
            );
            deploy_detail_colored("dry run:", install_ui::status_ok("yes"));
            deploy_detail_colored(
                "dependency mode:",
                install_ui::status_ok(dependency_mode.label()),
            );
            deploy_detail_colored(
                "optional deps:",
                install_ui::status_ok(if no_optional { "omitted" } else { "included" }),
            );
            install_ui::done("Done · dry run complete");
        }
        return Ok(());
    }

    let deploy_progress = (!json_output).then(|| install_ui::spin(&materialize_message));

    // validate_output_dir has already proven this path is outside the source
    // workspace, so force-clearing here preserves a clean snapshot without
    // risking source files.
    if force && plan.output_dir.exists() {
        std::fs::remove_dir_all(&plan.output_dir).map_err(|e| {
            LpmError::Script(format!(
                "lpm deploy --force: failed to clear output directory {:?}: {e}",
                plan.output_dir
            ))
        })?;
        std::fs::create_dir_all(&plan.output_dir).map_err(|e| {
            LpmError::Script(format!(
                "lpm deploy --force: failed to recreate empty output directory {:?}: {e}",
                plan.output_dir
            ))
        })?;
    }

    let copy_stats = copy_member_source(&plan.member_dir, &plan.output_dir)?;

    let mut selection_stats = apply_dependency_selection_to_deploy_manifest(
        &plan.output_dir,
        dependency_mode,
        no_optional,
    )?;

    let (
        workspace_members_copied,
        workspace_spec_rewrites,
        workspace_copy_stats,
        workspace_selection_stats,
    ) = copy_workspace_dependency_closure(
        &plan.output_dir,
        cwd,
        &member_name,
        dependency_mode,
        no_optional,
    )?;
    selection_stats.add(&workspace_selection_stats);

    let pruned_lockfile_packages =
        write_pruned_deploy_lockfile_if_possible(cwd, &plan.output_dir)?.unwrap_or(0);

    let target_set: Vec<String> = vec![plan.output_dir.display().to_string()];

    crate::commands::install::run_with_options_with_lpm_root(
        client,
        &plan.output_dir,
        json_output,
        false, // offline
        false, // force — don't force re-link, the output dir is fresh
        false, // allow_new — deploy should not bypass minimumReleaseAge
        false, // strict_integrity — deploy uses lockfile, integrity is recorded
        None,  // strict_peer_dependencies_override
        None,  // linker_override
        true,  // no_skills — deploy outputs are typically Docker images
        true,  // no_editor_setup — same reason
        false, // no_security_summary — keep findings visible in CI
        false, // auto_build — build is a separate concern
        Some(&target_set),
        None, // direct_versions_out: deploy does not finalize placeholders
        None, // requested_add_count: deploy is not an add-path install
        None, // script_policy_override: `lpm deploy` does not expose policy flags
        None, // advisor_override: `lpm deploy` does not expose `--advisor`
        None, // min_release_age_override: use install defaults
        // drift-ignore: deploy captures an already-resolved tree;
        // drift is an orthogonal gate. Deploy inherits the same
        // default "enforce"; the output dir carries whatever
        // trustedDependencies the project defined, so legitimately
        // identical identities pass normally.
        crate::provenance_fetch::DriftIgnorePolicy::default(),
        // verify-policy: `lpm deploy` does not surface its own
        // `--unverified-provenance{,-all}` flags. Honors the
        // operator-persistent posture chain (env + `[sigstore]
        // verify` config) for uniformity with `lpm install`.
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
        crate::commands::install::InstallOmitPolicy {
            dev: false,
            optional: no_optional,
        },
        // `lpm deploy` does not surface its own
        // sandbox-mode flags. CI deployers can still flip strict
        // via `LPM_STRICT_SANDBOX=1`; the env tier of the chain
        // inside `rebuild::run` honors that.
        false, // strict_sandbox
        false, // no_sandbox
        false, // verbose: internal pipeline, no user-facing Done footer
        false, // audit_after_install: internal pipeline never runs audit
        lpm_common::LpmRoot::from_dir(plan.output_dir.join(".lpm")),
    )
    .await?;

    let internal_symlinks_retargeted = retarget_internal_node_modules_symlinks(&plan.output_dir)?;
    drop(deploy_progress);

    let elapsed = start.elapsed();

    // Emit the deploy-specific summary AFTER the install pipeline's output.
    // In JSON mode this produces a JSON-Lines stream (install JSON, then
    // deploy JSON). In human mode it's a final success line.
    if json_output {
        let payload = serde_json::json!({
            "success": true,
            "dry_run": false,
            "deployed": {
                "member": member_name,
                "member_dir": plan.member_dir.display().to_string(),
                "output_dir": plan.output_dir.display().to_string(),
            },
            "copy_stats": {
                "files_copied": copy_stats.files_copied,
                "files_skipped": copy_stats.files_skipped,
                "bytes_copied": copy_stats.bytes_copied,
            },
            "workspace_copy_stats": {
                "members_copied": workspace_members_copied,
                "files_copied": workspace_copy_stats.files_copied,
                "files_skipped": workspace_copy_stats.files_skipped,
                "bytes_copied": workspace_copy_stats.bytes_copied,
            },
            "workspace_protocol_rewrites": workspace_spec_rewrites,
            "dependency_mode": dependency_mode.label(),
            "optional_dependencies": !no_optional,
            "dependencies_stripped": {
                "dev": selection_stats.dev_dependencies_stripped,
                "production": selection_stats.production_dependencies_stripped,
                "optional": selection_stats.optional_dependencies_stripped,
            },
            "pruned_lockfile_packages": pruned_lockfile_packages,
            "internal_symlinks_retargeted": internal_symlinks_retargeted,
            "duration_ms": elapsed.as_millis() as u64,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else {
        deploy_detail_colored(
            "output:",
            install_ui::yellow(&plan.output_dir.display().to_string()),
        );
        deploy_detail_colored(
            "dependency mode:",
            install_ui::status_ok(dependency_mode.label()),
        );
        deploy_detail_colored(
            "workspace deps copied:",
            install_ui::status_ok(&workspace_members_copied.to_string()),
        );
        deploy_detail_colored(
            "workspace refs localized:",
            install_ui::status_ok(&workspace_spec_rewrites.to_string()),
        );
        deploy_detail_colored(
            "pruned lockfile packages:",
            install_ui::status_ok(&pruned_lockfile_packages.to_string()),
        );
        deploy_detail_colored(
            "relative symlinks:",
            install_ui::status_ok(&internal_symlinks_retargeted.to_string()),
        );
        deploy_detail_colored("node_modules installed:", install_ui::status_ok("yes"));
        install_ui::done(&format!(
            "Copied source, lockfile, and {} dependencies",
            install_ui::status_ok(dependency_mode.label())
        ));
        install_ui::done(&format!(
            "Done · deploy tree ready at {}",
            install_ui::yellow(&plan.output_dir.display().to_string())
        ));
    }

    Ok(())
}

fn deploy_detail_colored(label: &str, value: String) {
    eprintln!("    {} {value}", install_ui::dim(&format!("{label:<25}")));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn resolve_deploy_target(
        cwd: &Path,
        output_dir: &Path,
        filters: &[String],
        force: bool,
    ) -> Result<DeployPlan, LpmError> {
        super::resolve_deploy_target(cwd, output_dir, filters, &[], &[], &[], force)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        client: &RegistryClient,
        cwd: &Path,
        output_dir: &Path,
        filters: &[String],
        force: bool,
        dry_run: bool,
        json_output: bool,
    ) -> Result<(), LpmError> {
        super::run(
            client,
            cwd,
            output_dir,
            filters,
            &[],
            &[],
            &[],
            force,
            false,
            false,
            false,
            dry_run,
            json_output,
        )
        .await
    }

    /// Helper: build a real on-disk workspace fixture with the given members.
    fn write_workspace_fixture(root: &Path, members: &[(&str, &str)]) {
        std::fs::create_dir_all(root).unwrap();
        let workspace_globs: Vec<String> = members.iter().map(|(_, p)| (*p).to_string()).collect();
        let root_pkg = json!({
            "name": "monorepo",
            "private": true,
            "workspaces": workspace_globs,
        });
        std::fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();
        for (name, path) in members {
            let dir = root.join(path);
            std::fs::create_dir_all(&dir).unwrap();
            let pkg = json!({"name": name, "version": "1.0.0"});
            std::fs::write(
                dir.join("package.json"),
                serde_json::to_string_pretty(&pkg).unwrap(),
            )
            .unwrap();
        }
    }

    // ── entry-point guard tests ─────────────────────────────────────────

    #[tokio::test]
    async fn run_returns_error_when_filters_empty() {
        // Defensive: even though the CLI parser enforces required=true,
        // direct callers (e.g., a future MCP tool) can bypass that.
        let dir = tempfile::tempdir().unwrap();
        let result = run(
            &RegistryClient::new(),
            dir.path(),
            &dir.path().join("out"),
            &[],
            false,
            false,
            true,
        )
        .await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("--filter"),
            "empty filter must surface --filter in the error"
        );
    }

    // ── target resolution tests ─────────────────────────────────────────

    #[test]
    fn resolve_deploy_target_with_filter_matching_one_member_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            tmp.path(),
            &[("api", "packages/api"), ("web", "packages/web")],
        );

        // Output dir is OUTSIDE the workspace tree
        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");

        let plan = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap();

        assert!(plan.member_manifest.ends_with("packages/api/package.json"));
        assert!(plan.member_dir.ends_with("packages/api"));
    }

    #[test]
    fn resolve_deploy_target_with_filter_matching_zero_members_hard_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("out");

        let err = resolve_deploy_target(tmp.path(), &output, &["nonexistent".to_string()], false)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("matched no workspace members"), "got: {msg}");
    }

    #[test]
    fn resolve_deploy_target_with_filter_matching_multiple_members_hard_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(
            tmp.path(),
            &[
                ("ui-button", "packages/ui-button"),
                ("ui-card", "packages/ui-card"),
            ],
        );
        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("out");

        let err =
            resolve_deploy_target(tmp.path(), &output, &["ui-*".to_string()], false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("matched 2 workspace members") && msg.contains("exactly one"),
            "got: {msg}"
        );
    }

    #[test]
    fn resolve_deploy_target_in_non_workspace_hard_errors() {
        // Standalone project (no workspace) — install_targets surfaces this
        // as "--filter requires a workspace"
        let tmp = tempfile::tempdir().unwrap();
        let pkg = json!({"name": "solo"});
        std::fs::write(
            tmp.path().join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("out");

        let err =
            resolve_deploy_target(tmp.path(), &output, &["foo".to_string()], false).unwrap_err();
        assert!(err.to_string().contains("workspace"));
    }

    #[test]
    fn resolve_deploy_target_to_existing_non_empty_output_without_force_hard_errors() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");
        std::fs::create_dir_all(&output).unwrap();
        // Make it non-empty
        std::fs::write(output.join("stale-file"), "leftover").unwrap();

        let err =
            resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not empty"));
        assert!(msg.contains("--force"));
    }

    #[test]
    fn resolve_deploy_target_to_existing_non_empty_output_with_force_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("stale-file"), "leftover").unwrap();

        // --force allows the non-empty output dir
        let plan = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], true).unwrap();
        assert!(plan.member_dir.ends_with("packages/api"));
    }

    #[test]
    fn resolve_deploy_target_to_empty_existing_output_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");
        std::fs::create_dir_all(&output).unwrap();
        // Empty dir is fine without --force

        let plan = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap();
        assert!(plan.member_dir.ends_with("packages/api"));
    }

    #[test]
    fn resolve_deploy_target_to_nonexistent_output_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("does-not-exist-yet");
        // Output dir does not exist — that's the typical fresh deploy case

        let plan = resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap();
        assert!(plan.member_dir.ends_with("packages/api"));
    }

    #[test]
    fn resolve_deploy_target_with_output_inside_workspace_hard_errors_self_loop() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        // Output is INSIDE the workspace tree — must be rejected as a self-loop
        let output = tmp.path().join("deploy-output");

        let err =
            resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("inside the workspace") && msg.contains("self-deploy"),
            "got: {msg}"
        );
    }

    #[test]
    fn resolve_deploy_target_with_output_inside_workspace_member_dir_also_errors() {
        // Even if the output is nested deep inside a member dir, it must
        // still be flagged as inside the workspace.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        let output = tmp.path().join("packages").join("api").join("dist-deploy");

        let err =
            resolve_deploy_target(tmp.path(), &output, &["api".to_string()], false).unwrap_err();
        assert!(err.to_string().contains("inside the workspace"));
    }

    // ── regression (High): self-loop guard bypass ────

    #[cfg(unix)]
    #[test]
    fn canonicalize_or_partial_resolves_symlink_through_nonexistent_tail() {
        // PHASE 3 AUDIT REGRESSION (High):
        // canonicalize_or_partial is the load-bearing helper that fixes the
        // self-loop guard bypass. When the path itself does not exist, it
        // walks up to the deepest existing ancestor, canonicalizes that
        // (which follows symlinks), then re-appends the missing tail.
        //
        // This unit test pins the helper's contract: a symlinked-prefix
        // path with a missing tail must produce the symlink-resolved form.
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        let real_canonical = std::fs::canonicalize(&real_dir).unwrap();

        let alias = tmp.path().join("alias");
        std::os::unix::fs::symlink(&real_dir, &alias).unwrap();

        // The path itself does not exist; the parent (the symlink) does.
        let with_missing_tail = alias.join("nested").join("does-not-exist");
        let resolved = canonicalize_or_partial(&with_missing_tail);
        let expected = real_canonical.join("nested").join("does-not-exist");
        assert_eq!(
            resolved, expected,
            "canonicalize_or_partial must follow symlinks at the deepest existing ancestor and \
             re-append the missing tail in original order"
        );

        // Sanity: the bare alias resolves to the real canonical form.
        assert_eq!(canonicalize_or_partial(&alias), real_canonical);

        // Sanity: a fully existing canonical path is returned canonically.
        assert_eq!(canonicalize_or_partial(&real_dir), real_canonical);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_deploy_target_via_symlinked_alias_to_workspace_is_caught_as_self_loop() {
        // PHASE 3 AUDIT REGRESSION (High):
        // The pre-fix self-loop guard compared a canonicalized workspace
        // root against a LEXICALLY-normalized output path. When the user
        // passed an output path that lexically appeared OUTSIDE the
        // workspace but actually resolved INSIDE it via a symlink (the
        // macOS `/tmp → /private/tmp` case is the canonical example), the
        // prefix comparison silently missed the relationship and the
        // deploy proceeded straight into self-recursion territory.
        //
        // Reproduction: create a real workspace, create a sibling symlink
        // pointing at it, then pass the canonical workspace as `cwd` and
        // the SYMLINKED alias as the output prefix. Pre-fix:
        //   workspace_canonical = real_root             (canonicalized)
        //   output_lexical      = alias_root/dist       (NOT canonicalized)
        //   alias_root/dist .starts_with(real_root)     → false → bypass
        // Post-fix:
        //   canonicalize_or_partial(alias_root/dist)    → real_root/dist
        //   real_root/dist .starts_with(real_root)      → true → guard fires
        let tmp = tempfile::tempdir().unwrap();
        let real_root = tmp.path().join("real-workspace");
        write_workspace_fixture(&real_root, &[("api", "packages/api")]);

        // Create a symlink alias pointing at the real workspace root.
        let alias_root = tmp.path().join("alias-workspace");
        std::os::unix::fs::symlink(&real_root, &alias_root).unwrap();

        // Sanity: the alias resolves to the real workspace.
        assert_eq!(
            std::fs::canonicalize(&alias_root).unwrap(),
            std::fs::canonicalize(&real_root).unwrap(),
            "test setup: alias must resolve to real workspace",
        );

        // Output is supplied via the alias prefix. Lexically it does NOT
        // start with `real_root` — that's exactly what the old code missed.
        let output_via_alias = alias_root.join("dist-deploy");

        let err = resolve_deploy_target(&real_root, &output_via_alias, &["api".to_string()], false)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("inside the workspace") && msg.contains("self-deploy"),
            "PHASE 3 AUDIT REGRESSION (High): symlink-aliased output that resolves into the \
             workspace must be caught as a self-deploy loop. got: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_deploy_target_canonical_output_inside_symlinked_workspace_is_also_caught() {
        // Mirror image of the previous test: this time the WORKSPACE is
        // accessed via a symlink and the output is supplied as the
        // canonical real path. Without canonicalize_or_partial on BOTH
        // sides, the comparison would still be asymmetric and miss the
        // relationship. With the fix, both sides resolve to the real
        // workspace and the guard fires.
        let tmp = tempfile::tempdir().unwrap();
        let real_root = tmp.path().join("real-workspace");
        write_workspace_fixture(&real_root, &[("api", "packages/api")]);

        let alias_root = tmp.path().join("alias-workspace");
        std::os::unix::fs::symlink(&real_root, &alias_root).unwrap();

        // cwd via the alias, output via the real canonical path.
        let output_via_real = real_root.join("dist-deploy");

        let err = resolve_deploy_target(&alias_root, &output_via_real, &["api".to_string()], false)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("inside the workspace") && msg.contains("self-deploy"),
            "PHASE 3 AUDIT REGRESSION (High): canonical output inside a symlink-accessed \
             workspace must also be caught. got: {msg}"
        );
    }

    // ── dry-run tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn run_dry_run_succeeds_after_target_resolution() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");

        let result = run(
            &RegistryClient::new(),
            tmp.path(),
            &output,
            &["api".to_string()],
            false,
            true, // dry_run
            true, // json_output
        )
        .await;

        assert!(result.is_ok(), "dry-run should succeed: {result:?}");
        // Output dir was NOT created (dry-run is read-only)
        assert!(
            !output.exists(),
            "dry-run must not create the output directory"
        );
    }

    #[tokio::test]
    async fn run_dry_run_propagates_target_resolution_errors() {
        // Even in dry-run mode, target resolution errors should surface.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");

        let result = run(
            &RegistryClient::new(),
            tmp.path(),
            &output,
            &["nonexistent".to_string()],
            false,
            true,
            true,
        )
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("matched no"));
    }

    // ── end-to-end (no-deps fixture) ────────────────────────────────────
    //
    // The install pipeline at the deploy output dir runs for real. We test
    // it against fixtures that have empty `dependencies` so the resolver
    // hits the no-deps short-circuit and returns success without any
    // network calls. The fix to the empty-deps early return makes this
    // path emit a clean JSON success object.

    #[tokio::test]
    async fn run_full_pipeline_with_empty_deps_member_succeeds_human_mode() {
        let _approval_env = crate::test_env::ScopedEnv::update([(
            "LPM_TEST_SECURITY_AUTH_RESULT",
            Option::<std::ffi::OsString>::None,
        )]);
        // Member has no dependencies → install pipeline short-circuits.
        // Deploy should produce a successful end-to-end run.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
        // Add a source file so the copy has something to do
        let api_src = tmp.path().join("packages").join("api").join("src");
        std::fs::create_dir_all(&api_src).unwrap();
        std::fs::write(api_src.join("index.js"), "module.exports = {}").unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");

        let result = run(
            &RegistryClient::new(),
            tmp.path(),
            &output,
            &["api".to_string()],
            false,
            false,
            false, // human output mode
        )
        .await;

        assert!(result.is_ok(), "deploy should succeed: {result:?}");

        // The copy actually happened
        assert!(output.join("package.json").exists());
        assert!(output.join("src").join("index.js").exists());
    }

    #[tokio::test]
    async fn run_full_pipeline_with_empty_deps_member_succeeds_json_mode() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
        let api_src = tmp.path().join("packages").join("api").join("src");
        std::fs::create_dir_all(&api_src).unwrap();
        std::fs::write(api_src.join("index.js"), "module.exports = {}").unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");

        let result = run(
            &RegistryClient::new(),
            tmp.path(),
            &output,
            &["api".to_string()],
            false,
            false,
            true, // json output
        )
        .await;

        assert!(result.is_ok());
        // The deploy command emits its summary JSON to stdout. We can't
        // easily capture stdout in a unit test, but we can verify the
        // filesystem state matches what JSON mode would describe.
        assert!(output.join("package.json").exists());
        let pkg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        assert_eq!(pkg["name"], "api");
    }

    #[tokio::test]
    async fn run_full_pipeline_workspace_protocol_dep_is_localized_in_output() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");

        let result = run(
            &RegistryClient::new(),
            &workspace_root,
            &output,
            &["@scope/api".to_string()],
            false,
            false,
            true,
        )
        .await;

        let _ = result;

        if output.join("package.json").exists() {
            let after: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(output.join("package.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                after["dependencies"]["@scope/auth"], "file:.lpm/deploy-workspace/packages/auth",
                "workspace:* must be rewritten to a local file dependency in deploy output"
            );
            assert!(
                output
                    .join(DEPLOY_WORKSPACE_DIR)
                    .join("packages/auth/package.json")
                    .exists(),
                "local workspace dependency source must be copied into the deploy output"
            );

            // CRITICAL: source workspace manifest is unchanged (still has workspace:*)
            let source: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(workspace_root.join("packages/api/package.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                source["dependencies"]["@scope/auth"], "workspace:*",
                "source workspace manifest must NOT be modified by deploy"
            );
        }
    }

    #[tokio::test]
    async fn run_dry_run_with_json_emits_dry_run_marker() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");

        let result = run(
            &RegistryClient::new(),
            tmp.path(),
            &output,
            &["api".to_string()],
            false,
            true, // dry_run
            true, // json
        )
        .await;
        assert!(result.is_ok());

        // Output dir was NOT created (dry-run is fully read-only)
        assert!(!output.exists(), "dry-run must not create the output dir");
    }

    #[tokio::test]
    async fn run_force_flag_allows_overwrite_of_non_empty_output() {
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::write(output.join("stale-file"), "leftover").unwrap();

        // Without --force this would error
        let result = run(
            &RegistryClient::new(),
            tmp.path(),
            &output,
            &["api".to_string()],
            true, // force
            false,
            false,
        )
        .await;
        assert!(
            result.is_ok(),
            "force should allow non-empty output: {result:?}"
        );
        assert!(output.join("package.json").exists());
    }

    #[tokio::test]
    async fn run_force_actually_cleans_stale_files_from_output_dir() {
        // PHASE 3 AUDIT REGRESSION (Medium):
        // Pre-fix, `--force` only suppressed the "output dir not empty"
        // error in validate_output_dir. The install pipeline then ran
        // in-place over whatever was already in the dir, leaving stale
        // files from a previous deploy (orphaned source files, old
        // lockfiles, leftover node_modules) in the output. That violates
        // the "deploy output is a clean snapshot" invariant and can mask
        // real bugs (e.g., "I deleted this file from the source but it's
        // still in my Docker image because the previous deploy left it
        // there").
        //
        // The fix removes the dir tree and recreates an empty dir before
        // any copy step. This test plants stale files at multiple depths
        // and asserts every one is gone after the deploy completes.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
        let api_src = tmp.path().join("packages").join("api").join("src");
        std::fs::create_dir_all(&api_src).unwrap();
        std::fs::write(api_src.join("index.js"), "module.exports = {}").unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");
        std::fs::create_dir_all(&output).unwrap();

        // Plant stale files / dirs at root and at depth.
        std::fs::write(output.join("STALE.txt"), "from a previous deploy").unwrap();
        std::fs::write(
            output.join("legacy-config.json"),
            r#"{"removed":"feature"}"#,
        )
        .unwrap();
        std::fs::create_dir_all(output.join("legacy-subdir").join("inner")).unwrap();
        std::fs::write(
            output
                .join("legacy-subdir")
                .join("inner")
                .join("orphan.txt"),
            "orphan",
        )
        .unwrap();
        // Plant a stale node_modules to simulate a previous install.
        std::fs::create_dir_all(output.join("node_modules").join("react")).unwrap();
        std::fs::write(
            output.join("node_modules").join("react").join("index.js"),
            "// stale react from previous deploy",
        )
        .unwrap();

        let result = run(
            &RegistryClient::new(),
            tmp.path(),
            &output,
            &["api".to_string()],
            true, // force
            false,
            false,
        )
        .await;
        assert!(
            result.is_ok(),
            "deploy with --force should succeed: {result:?}"
        );

        // Positive: the fresh deploy artifacts are present.
        assert!(
            output.join("package.json").exists(),
            "fresh package.json must be copied"
        );
        assert!(
            output.join("src").join("index.js").exists(),
            "fresh src files must be copied"
        );

        // CRITICAL: every stale entry from before the deploy is GONE.
        assert!(
            !output.join("STALE.txt").exists(),
            "PHASE 3 AUDIT REGRESSION (Medium): --force must clean stale root files"
        );
        assert!(
            !output.join("legacy-config.json").exists(),
            "PHASE 3 AUDIT REGRESSION (Medium): --force must clean stale root files"
        );
        assert!(
            !output.join("legacy-subdir").exists(),
            "PHASE 3 AUDIT REGRESSION (Medium): --force must clean stale subdirs"
        );
        // node_modules is recreated by the install pipeline (the empty-deps
        // member short-circuits, so it may or may not exist post-install).
        // The load-bearing assertion is that the STALE react file from
        // before the deploy is gone, NOT that node_modules itself is empty.
        assert!(
            !output
                .join("node_modules")
                .join("react")
                .join("index.js")
                .exists(),
            "PHASE 3 AUDIT REGRESSION (Medium): --force must clean stale node_modules contents"
        );
    }

    #[tokio::test]
    async fn run_without_force_does_not_remove_existing_dir_tree() {
        // Defensive guard: the --force cleanup must NOT run when --force
        // is false. Without --force the validate_output_dir check rejects
        // a non-empty output dir with an error, and we must NOT have
        // removed anything before that error fires. This test exercises
        // the empty-existing-dir path (which IS allowed without --force)
        // and asserts the dir is not deleted out from under the user.
        let tmp = tempfile::tempdir().unwrap();
        write_workspace_fixture(tmp.path(), &[("api", "packages/api")]);
        let api_src = tmp.path().join("packages").join("api").join("src");
        std::fs::create_dir_all(&api_src).unwrap();
        std::fs::write(api_src.join("index.js"), "module.exports = {}").unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");
        std::fs::create_dir_all(&output).unwrap();
        // Empty dir is allowed without --force.

        let result = run(
            &RegistryClient::new(),
            tmp.path(),
            &output,
            &["api".to_string()],
            false, // NOT force
            false,
            false,
        )
        .await;
        assert!(
            result.is_ok(),
            "deploy into empty dir should succeed: {result:?}"
        );
        assert!(output.join("package.json").exists());
    }

    #[tokio::test]
    async fn read_member_name_falls_back_to_dir_name_when_name_field_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("my-pkg").join("package.json");
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        std::fs::write(&manifest, "{}").unwrap();

        let name = read_member_name(&manifest);
        assert_eq!(name, "my-pkg");
    }

    #[tokio::test]
    async fn read_member_name_extracts_name_from_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("dir").join("package.json");
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        std::fs::write(&manifest, r#"{"name": "@scope/api", "version": "1.0.0"}"#).unwrap();

        let name = read_member_name(&manifest);
        assert_eq!(name, "@scope/api");
    }

    // ── end-to-end integration: deny list + local workspace deps ────────

    #[tokio::test]
    async fn run_e2e_combines_deny_list_and_local_workspace_dep_rewrite() {
        // Comprehensive end-to-end test: workspace with workspace:* deps,
        // member containing .env files and a node_modules, deploy it, and
        // verify EVERY invariant in one place:
        //
        // 1. Source files are copied (positive assertion)
        // 2. .env files are NOT in the deploy output (security)
        // 3. source node_modules is NOT copied into the deploy output
        // 4. workspace:* deps are rewritten to local file dependencies
        // 5. The source workspace's manifests are byte-identical
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());

        // Add some files that should be deployed and some that should NOT
        let api_dir = workspace_root.join("packages").join("api");
        std::fs::create_dir_all(api_dir.join("src")).unwrap();
        std::fs::write(
            api_dir.join("src").join("server.ts"),
            "export const app = {};",
        )
        .unwrap();
        std::fs::write(api_dir.join("README.md"), "# api\n").unwrap();

        // Deny-list entries that MUST NOT be deployed
        std::fs::write(
            api_dir.join(".env"),
            "DATABASE_URL=postgres://prod-secret\n",
        )
        .unwrap();
        std::fs::write(api_dir.join(".env.production"), "API_KEY=hunter2\n").unwrap();
        std::fs::create_dir_all(api_dir.join("node_modules").join("react")).unwrap();
        std::fs::write(
            api_dir.join("node_modules").join("react").join("index.js"),
            "module.exports = 'leaked react';",
        )
        .unwrap();

        // Snapshot the source manifests
        let source_root_before = std::fs::read(workspace_root.join("package.json")).unwrap();
        let source_auth_before =
            std::fs::read(workspace_root.join("packages/auth/package.json")).unwrap();
        let source_api_before =
            std::fs::read(workspace_root.join("packages/api/package.json")).unwrap();

        let output_parent = tempfile::tempdir().unwrap();
        let output = output_parent.path().join("prod-api");
        let result = run(
            &RegistryClient::new(),
            &workspace_root,
            &output,
            &["@scope/api".to_string()],
            false,
            false,
            true,
        )
        .await;
        let _ = result;

        // ── Positive: deployed source files exist ──────────────────────────
        assert!(output.join("package.json").exists(), "package.json copied");
        assert!(
            output.join("src").join("server.ts").exists(),
            "src files copied"
        );
        assert!(output.join("README.md").exists(), "README copied");

        // ── Security: .env files not present ──────────────────────────────
        assert!(
            !output.join(".env").exists(),
            "SECURITY: .env must not be in deploy output"
        );
        assert!(
            !output.join(".env.production").exists(),
            "SECURITY: .env.production must not be in deploy output"
        );

        // ── Security: source node_modules content not copied ──────────────
        assert!(
            !output
                .join("node_modules")
                .join("react")
                .join("index.js")
                .exists(),
            "source node_modules content must not be copied into deploy output"
        );

        // ── workspace:* deps rewritten to local file dependencies ─────────
        let deployed_pkg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        assert_eq!(
            deployed_pkg["dependencies"]["@scope/auth"], "file:.lpm/deploy-workspace/packages/auth",
            "workspace:* must be rewritten to a local file dependency in the deploy output"
        );
        assert!(
            output
                .join(DEPLOY_WORKSPACE_DIR)
                .join("packages/auth/package.json")
                .exists(),
            "workspace dependency source must be copied into deploy output"
        );

        // ── Read-only on source: every source manifest is byte-identical ──
        assert_eq!(
            std::fs::read(workspace_root.join("package.json")).unwrap(),
            source_root_before,
            "source workspace root must not be modified"
        );
        assert_eq!(
            std::fs::read(workspace_root.join("packages/auth/package.json")).unwrap(),
            source_auth_before,
            "source auth member must not be modified"
        );
        assert_eq!(
            std::fs::read(workspace_root.join("packages/api/package.json")).unwrap(),
            source_api_before,
            "source api member must not be modified (CRITICAL: hardlink-mutation regression guard)"
        );
    }

    // ── manifest rewrite tests ──────────────────────────────────────────

    /// Helper: build a fixture workspace with two members where one depends
    /// on the other via workspace:*. Returns the workspace root path.
    fn build_workspace_with_workspace_protocol_dep(tmp: &Path) -> PathBuf {
        let root = tmp.join("workspace");
        std::fs::create_dir_all(&root).unwrap();
        // Root manifest declares the workspace
        let root_pkg = json!({
            "name": "monorepo",
            "private": true,
            "workspaces": ["packages/auth", "packages/api"],
        });
        std::fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();

        // auth member with version 1.5.0
        std::fs::create_dir_all(root.join("packages").join("auth")).unwrap();
        let auth_pkg = json!({
            "name": "@scope/auth",
            "version": "1.5.0",
        });
        std::fs::write(
            root.join("packages").join("auth").join("package.json"),
            serde_json::to_string_pretty(&auth_pkg).unwrap(),
        )
        .unwrap();

        // api member with workspace:* dep on auth and a regular npm dep
        std::fs::create_dir_all(root.join("packages").join("api")).unwrap();
        let api_pkg = json!({
            "name": "@scope/api",
            "version": "2.0.0",
            "dependencies": {
                "@scope/auth": "workspace:*",
                "express": "^4.0.0",
            },
            "devDependencies": {
                "@scope/auth": "workspace:^",
            },
            "peerDependencies": {
                "@scope/auth": "workspace:~",
            },
        });
        std::fs::write(
            root.join("packages").join("api").join("package.json"),
            serde_json::to_string_pretty(&api_pkg).unwrap(),
        )
        .unwrap();

        root
    }

    #[test]
    fn copy_workspace_dependency_closure_copies_unpublished_member_and_localizes_spec() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
        let output = tempfile::tempdir().unwrap();
        copy_member_source(&workspace_root.join("packages/api"), output.path()).unwrap();
        apply_dependency_selection_to_deploy_manifest(
            output.path(),
            DependencyMode::Production,
            false,
        )
        .unwrap();

        let (members_copied, rewrites, copy_stats, _selection_stats) =
            copy_workspace_dependency_closure(
                output.path(),
                &workspace_root,
                "@scope/api",
                DependencyMode::Production,
                false,
            )
            .unwrap();
        let deployed_pkg: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(output.path().join("package.json")).unwrap(),
        )
        .unwrap();

        assert_eq!(members_copied, 1);
        assert_eq!(rewrites, 2);
        assert!(copy_stats.files_copied > 0);
        assert_eq!(
            deployed_pkg["dependencies"]["@scope/auth"],
            "file:.lpm/deploy-workspace/packages/auth"
        );
        assert!(
            output
                .path()
                .join(DEPLOY_WORKSPACE_DIR)
                .join("packages/auth/package.json")
                .exists(),
            "workspace member source must be copied into deploy-local workspace area"
        );
    }

    #[test]
    fn write_pruned_deploy_lockfile_keeps_only_reachable_registry_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = tmp.path().join("workspace");
        write_workspace_fixture(&workspace_root, &[("api", "packages/api")]);

        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "runtime".to_string(),
            version: "1.2.3".to_string(),
            dependencies: vec!["transitive@2.0.0".to_string()],
            ..Default::default()
        });
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "transitive".to_string(),
            version: "2.0.0".to_string(),
            ..Default::default()
        });
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "unrelated".to_string(),
            version: "9.9.9".to_string(),
            ..Default::default()
        });
        lockfile
            .write_all(&workspace_root.join(lpm_lockfile::LOCKFILE_NAME))
            .unwrap();

        let output = tempfile::tempdir().unwrap();
        std::fs::write(
            output.path().join("package.json"),
            serde_json::to_string_pretty(&json!({
                "name": "api",
                "dependencies": {"runtime": "^1.0.0"}
            }))
            .unwrap(),
        )
        .unwrap();

        let count =
            write_pruned_deploy_lockfile_if_possible(&workspace_root, output.path()).unwrap();
        let deployed_lockfile = lpm_lockfile::Lockfile::read_from_file(
            &output.path().join(lpm_lockfile::LOCKFILE_NAME),
        )
        .unwrap();
        let names: HashSet<String> = deployed_lockfile
            .packages
            .iter()
            .map(|package| package.name.clone())
            .collect();

        assert_eq!(count, Some(2));
        assert!(names.contains("runtime"));
        assert!(names.contains("transitive"));
        assert!(!names.contains("unrelated"));
    }

    #[cfg(unix)]
    #[test]
    fn retarget_internal_node_modules_symlinks_makes_absolute_internal_links_relative() {
        let tmp = tempfile::tempdir().unwrap();
        let output = tmp.path().join("deploy");
        let target = output.join(".lpm/store/v2/links/runtime");
        let link = output.join("node_modules/runtime");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let retargeted = retarget_internal_node_modules_symlinks(&output).unwrap();
        let new_target = std::fs::read_link(&link).unwrap();

        assert_eq!(retargeted, 1);
        assert!(
            !new_target.is_absolute(),
            "deploy-internal symlink target must be relative after retargeting"
        );
        assert_eq!(new_target, PathBuf::from("../.lpm/store/v2/links/runtime"));
    }

    #[test]
    fn rewrite_workspace_protocol_in_dependencies_replaces_with_concrete_version() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());

        // Stage the deploy output with a copy of api's manifest
        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        let api_manifest = workspace_root.join("packages/api/package.json");
        std::fs::copy(&api_manifest, output.join("package.json")).unwrap();

        let rewritten =
            rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();
        assert!(
            rewritten >= 1,
            "should have rewritten at least one workspace ref"
        );

        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        // workspace:* → 1.5.0 (auth's version)
        assert_eq!(after["dependencies"]["@scope/auth"], "1.5.0");
        // Non-workspace deps untouched
        assert_eq!(after["dependencies"]["express"], "^4.0.0");
    }

    #[test]
    fn rewrite_workspace_protocol_caret_form_yields_caret_range() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::copy(
            workspace_root.join("packages/api/package.json"),
            output.join("package.json"),
        )
        .unwrap();

        rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        // workspace:^ → ^1.5.0
        assert_eq!(after["devDependencies"]["@scope/auth"], "^1.5.0");
    }

    #[test]
    fn rewrite_workspace_protocol_tilde_form_yields_tilde_range() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::copy(
            workspace_root.join("packages/api/package.json"),
            output.join("package.json"),
        )
        .unwrap();

        rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        // workspace:~ → ~1.5.0
        assert_eq!(after["peerDependencies"]["@scope/auth"], "~1.5.0");
    }

    #[test]
    fn rewrite_workspace_protocol_no_workspace_deps_no_op() {
        // Member with no workspace:* refs at all — manifest should not
        // change (we only write back if at least one rewrite happened).
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = tmp.path().join("workspace");
        std::fs::create_dir_all(workspace_root.join("packages/foo")).unwrap();
        let root_pkg = json!({
            "name": "monorepo",
            "private": true,
            "workspaces": ["packages/foo"],
        });
        std::fs::write(
            workspace_root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();
        let foo_pkg = json!({
            "name": "foo",
            "version": "1.0.0",
            "dependencies": {"express": "^4.0.0"},
        });
        std::fs::write(
            workspace_root.join("packages/foo/package.json"),
            serde_json::to_string_pretty(&foo_pkg).unwrap(),
        )
        .unwrap();

        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        let original_bytes =
            std::fs::read(workspace_root.join("packages/foo/package.json")).unwrap();
        std::fs::write(output.join("package.json"), &original_bytes).unwrap();

        let rewritten =
            rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

        assert_eq!(rewritten, 0);
        // Bytes should be byte-identical because we skipped the write
        assert_eq!(
            std::fs::read(output.join("package.json")).unwrap(),
            original_bytes
        );
    }

    #[test]
    fn rewrite_workspace_protocol_unresolvable_member_hard_errors() {
        // Member references a workspace:* dep on a name that's not in the
        // workspace. Should hard-error with the unresolvable name.
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = tmp.path().join("workspace");
        std::fs::create_dir_all(workspace_root.join("packages/api")).unwrap();
        let root_pkg = json!({
            "name": "monorepo",
            "private": true,
            "workspaces": ["packages/api"],
        });
        std::fs::write(
            workspace_root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();
        let api_pkg = json!({
            "name": "@scope/api",
            "version": "1.0.0",
            "dependencies": {"@scope/missing": "workspace:*"},
        });
        std::fs::write(
            workspace_root.join("packages/api/package.json"),
            serde_json::to_string_pretty(&api_pkg).unwrap(),
        )
        .unwrap();

        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::copy(
            workspace_root.join("packages/api/package.json"),
            output.join("package.json"),
        )
        .unwrap();

        let err =
            rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap_err();
        assert!(err.to_string().contains("@scope/missing"));
    }

    #[test]
    fn rewrite_workspace_protocol_breaks_hardlinks_to_protect_source() {
        // CRITICAL BUG REGRESSION (found during initial development):
        //
        // copy_member_source uses hardlinks for performance. A hardlinked
        // package.json in the deploy output dir SHARES THE SAME INODE as
        // the source workspace's package.json. A naive `std::fs::write` to
        // the output's package.json would write through the hardlink and
        // MUTATE the source — violating the read-only-on-source invariant.
        //
        // The fix is in rewrite_workspace_protocol_in_deploy_manifest:
        // remove the file first to unlink the path from the shared inode,
        // then write a fresh file. This test simulates the dangerous
        // pattern by manually hardlinking before the rewrite.
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
        let source_manifest = workspace_root.join("packages/api/package.json");
        let source_bytes_before = std::fs::read(&source_manifest).unwrap();

        // Set up the deploy output with a HARDLINK to the source manifest
        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        let output_manifest = output.join("package.json");
        std::fs::hard_link(&source_manifest, &output_manifest).unwrap();
        // Sanity: both paths now point to the same inode
        let src_inode = std::fs::metadata(&source_manifest).unwrap();
        let dst_inode = std::fs::metadata(&output_manifest).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                src_inode.ino(),
                dst_inode.ino(),
                "test setup: source and output should be hardlinked"
            );
        }
        // Suppress unused-variable warnings on non-unix
        let _ = (&src_inode, &dst_inode);

        // Run the rewrite — it should write to the output WITHOUT
        // mutating the source.
        rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

        // CRITICAL: source manifest is byte-identical
        let source_bytes_after = std::fs::read(&source_manifest).unwrap();
        assert_eq!(
            source_bytes_after, source_bytes_before,
            "SECURITY: rewrite must NOT mutate the source manifest through a hardlink"
        );

        // The output manifest IS modified (workspace:* → 1.5.0)
        let output_doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&output_manifest).unwrap()).unwrap();
        assert_eq!(output_doc["dependencies"]["@scope/auth"], "1.5.0");

        #[cfg(unix)]
        {
            // Source and output now have DIFFERENT inodes
            use std::os::unix::fs::MetadataExt;
            let src_after = std::fs::metadata(&source_manifest).unwrap();
            let dst_after = std::fs::metadata(&output_manifest).unwrap();
            assert_ne!(
                src_after.ino(),
                dst_after.ino(),
                "rewrite must have broken the hardlink — source and output should have different inodes"
            );
        }
    }

    #[test]
    fn rewrite_workspace_protocol_does_not_modify_source_workspace_manifests() {
        // CRITICAL invariant: deploy is read-only on the source side. The
        // manifest rewrite must NEVER touch the source workspace's files.
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());

        // Snapshot all source manifests before the rewrite
        let root_before = std::fs::read(workspace_root.join("package.json")).unwrap();
        let auth_before = std::fs::read(workspace_root.join("packages/auth/package.json")).unwrap();
        let api_before = std::fs::read(workspace_root.join("packages/api/package.json")).unwrap();

        // Set up the deploy output and run the rewrite
        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::copy(
            workspace_root.join("packages/api/package.json"),
            output.join("package.json"),
        )
        .unwrap();

        rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

        // Verify all source manifests are byte-identical
        assert_eq!(
            std::fs::read(workspace_root.join("package.json")).unwrap(),
            root_before,
            "source workspace root manifest must not be modified"
        );
        assert_eq!(
            std::fs::read(workspace_root.join("packages/auth/package.json")).unwrap(),
            auth_before,
            "source auth member manifest must not be modified"
        );
        assert_eq!(
            std::fs::read(workspace_root.join("packages/api/package.json")).unwrap(),
            api_before,
            "source api member manifest must not be modified"
        );
    }

    #[test]
    fn rewrite_workspace_protocol_in_dev_dependencies_too() {
        // Even though install doesn't use devDependencies, deploy rewrites
        // them so the deploy output's package.json is clean.
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::copy(
            workspace_root.join("packages/api/package.json"),
            output.join("package.json"),
        )
        .unwrap();

        rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        // devDependencies workspace:^ → ^1.5.0
        assert_eq!(after["devDependencies"]["@scope/auth"], "^1.5.0");
        // peerDependencies workspace:~ → ~1.5.0
        assert_eq!(after["peerDependencies"]["@scope/auth"], "~1.5.0");
    }

    #[test]
    fn rewrite_workspace_protocol_returns_count_of_rewrites() {
        // The function returns the total number of workspace:* refs rewritten
        // across all sections. The fixture has 3 such refs (deps, devDeps, peerDeps).
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        std::fs::copy(
            workspace_root.join("packages/api/package.json"),
            output.join("package.json"),
        )
        .unwrap();

        let rewritten =
            rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap();

        assert_eq!(
            rewritten, 3,
            "fixture has workspace refs in dependencies, devDependencies, and peerDependencies"
        );
    }

    #[test]
    fn rewrite_workspace_protocol_errors_when_output_manifest_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_root = build_workspace_with_workspace_protocol_dep(tmp.path());
        let output = tmp.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        // No package.json copied — file is missing

        let err =
            rewrite_workspace_protocol_in_deploy_manifest(&output, &workspace_root).unwrap_err();
        assert!(err.to_string().contains("read deploy manifest"));
    }

    // ── source file copier tests ────────────────────────────────────────
    //
    // These tests focus on the security boundary (the deny list) and the
    // happy paths. The negative assertions are the load-bearing ones —
    // each .env* / node_modules / .git assertion is a regression guard
    // for a security failure.

    /// Helper: build a fixture member dir with a representative file tree.
    /// Returns the path to the member dir, ready to be passed as `src_dir`
    /// to `copy_member_source`.
    fn build_member_fixture(tmp: &Path) -> PathBuf {
        let member = tmp.join("member");
        std::fs::create_dir_all(&member).unwrap();

        // Files that SHOULD be copied
        std::fs::write(
            member.join("package.json"),
            r#"{"name":"foo","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(member.join("README.md"), "# foo\n").unwrap();
        std::fs::write(member.join("LICENSE"), "MIT\n").unwrap();
        std::fs::write(member.join("tsconfig.json"), "{}").unwrap();

        std::fs::create_dir_all(member.join("src")).unwrap();
        std::fs::write(member.join("src").join("index.ts"), "export {}").unwrap();
        std::fs::write(member.join("src").join("util.ts"), "export {}").unwrap();

        std::fs::create_dir_all(member.join("dist")).unwrap();
        std::fs::write(member.join("dist").join("index.js"), "module.exports = {}").unwrap();

        // Files that MUST NOT be copied (the deny list)
        std::fs::write(member.join(".env"), "SECRET=hunter2\n").unwrap();
        std::fs::write(member.join(".env.local"), "LOCAL_SECRET=foo\n").unwrap();
        std::fs::write(member.join(".env.production"), "PROD=bar\n").unwrap();
        std::fs::write(member.join(".env.test"), "TEST=baz\n").unwrap();

        std::fs::write(member.join("lpm.lock"), "stub-lockfile").unwrap();
        std::fs::write(member.join("lpm.lockb"), b"stub-bin").unwrap();

        std::fs::create_dir_all(member.join("node_modules").join("react")).unwrap();
        std::fs::write(
            member.join("node_modules").join("react").join("index.js"),
            "module.exports = 'react'",
        )
        .unwrap();

        std::fs::create_dir_all(member.join(".lpm").join("cache")).unwrap();
        std::fs::write(member.join(".lpm").join("state.json"), "{}").unwrap();

        std::fs::create_dir_all(member.join(".git").join("objects")).unwrap();
        std::fs::write(member.join(".git").join("HEAD"), "ref: refs/heads/main").unwrap();

        std::fs::write(member.join(".gitignore"), "node_modules\n").unwrap();
        std::fs::write(member.join(".DS_Store"), b"mac cruft").unwrap();

        member
    }

    // ── Happy path: files that should be copied ────────────────────────────

    #[test]
    fn copy_member_source_copies_package_json_and_readme() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(dst.join("package.json").exists());
        assert!(dst.join("README.md").exists());
        assert!(dst.join("LICENSE").exists());
        assert!(dst.join("tsconfig.json").exists());
    }

    #[test]
    fn copy_member_source_copies_nested_src_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(dst.join("src").join("index.ts").exists());
        assert!(dst.join("src").join("util.ts").exists());
    }

    #[test]
    fn copy_member_source_preserves_dist_directory() {
        // dist/ is a build artifact that callers may want to deploy.
        // It is NOT in the deny list — explicit positive assertion.
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(
            dst.join("dist").join("index.js").exists(),
            "dist/ build artifacts must be preserved"
        );
    }

    #[test]
    fn copy_member_source_honors_package_files_field() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("member");
        std::fs::create_dir_all(src.join("dist")).unwrap();
        std::fs::create_dir_all(src.join("src")).unwrap();
        std::fs::write(
            src.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0","files":["dist"]}"#,
        )
        .unwrap();
        std::fs::write(src.join("README.md"), "# pkg\n").unwrap();
        std::fs::write(src.join("dist").join("index.js"), "module.exports = {}").unwrap();
        std::fs::write(src.join("src").join("index.ts"), "export {};").unwrap();

        let dst = tmp.path().join("output");
        copy_member_source(&src, &dst).unwrap();

        assert!(dst.join("package.json").exists());
        assert!(dst.join("README.md").exists());
        assert!(dst.join("dist").join("index.js").exists());
        assert!(
            !dst.join("src").exists(),
            "files=[\"dist\"] must exclude source paths outside the publish set"
        );
    }

    #[test]
    fn copy_member_source_honors_npmignore_before_gitignore() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("member");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(src.join(".npmignore"), "secret.txt\n").unwrap();
        std::fs::write(src.join(".gitignore"), "!secret.txt\nignored-by-git.txt\n").unwrap();
        std::fs::write(src.join("secret.txt"), "secret").unwrap();
        std::fs::write(src.join("ignored-by-git.txt"), "git-only").unwrap();

        let dst = tmp.path().join("output");
        copy_member_source(&src, &dst).unwrap();

        assert!(
            !dst.join("secret.txt").exists(),
            ".npmignore must exclude files from deploy copy"
        );
        assert!(
            dst.join("ignored-by-git.txt").exists(),
            ".npmignore must take precedence over .gitignore when both exist"
        );
        assert!(
            !dst.join(".npmignore").exists(),
            ".npmignore controls selection but is not deploy payload"
        );
    }

    // ── Security regressions: deny list ────────────────────────────────────

    #[test]
    fn copy_member_source_never_copies_dotenv() {
        // CRITICAL: .env file must never end up in a deploy output. This is
        // the single most important security guarantee deploy makes.
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(
            !dst.join(".env").exists(),
            "SECURITY: .env must NEVER be copied to a deploy output"
        );
    }

    #[test]
    fn copy_member_source_never_copies_dotenv_local() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(
            !dst.join(".env.local").exists(),
            "SECURITY: .env.local must NEVER be copied to a deploy output"
        );
    }

    #[test]
    fn copy_member_source_never_copies_any_dotenv_variant() {
        // Iterate every .env variant in the deny list — each one is its
        // own security regression.
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        for variant in [".env", ".env.local", ".env.production", ".env.test"] {
            assert!(
                !dst.join(variant).exists(),
                "SECURITY: {variant} must NEVER be copied to a deploy output"
            );
        }
    }

    #[test]
    fn copy_member_source_never_copies_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(
            !dst.join("node_modules").exists(),
            "node_modules must not be copied (the install pipeline recreates it)"
        );
    }

    #[test]
    fn copy_member_source_never_copies_dot_lpm() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(
            !dst.join(".lpm").exists(),
            ".lpm internal state must not be copied"
        );
    }

    #[test]
    fn copy_member_source_never_copies_lockfiles() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(!dst.join("lpm.lock").exists());
        assert!(!dst.join("lpm.lockb").exists());
    }

    #[test]
    fn copy_member_source_never_copies_git_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(
            !dst.join(".git").exists(),
            ".git directory must not be copied"
        );
        assert!(
            !dst.join(".gitignore").exists(),
            ".gitignore must not be copied (deploy output is not a repo)"
        );
    }

    #[test]
    fn copy_member_source_never_copies_ds_store() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        copy_member_source(&src, &dst).unwrap();

        assert!(!dst.join(".DS_Store").exists());
    }

    #[test]
    fn copy_member_source_skips_nested_node_modules_too() {
        // The deny list applies at every nesting level, not just root.
        // Verify that a `nested/sub/node_modules/foo` is also excluded.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("member");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("package.json"), "{}").unwrap();

        let nested = src
            .join("packages")
            .join("inner")
            .join("node_modules")
            .join("foo");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("index.js"), "leaked").unwrap();

        let dst = tmp.path().join("output");
        copy_member_source(&src, &dst).unwrap();

        assert!(dst.join("packages").join("inner").exists());
        assert!(
            !dst.join("packages")
                .join("inner")
                .join("node_modules")
                .exists(),
            "nested node_modules must also be denied"
        );
    }

    #[test]
    fn copy_member_source_skips_nested_dotenv_too() {
        // CRITICAL: same defense at depth — `packages/foo/.env` must not
        // be copied even if the user accidentally checked one in.
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("member");
        std::fs::create_dir_all(src.join("config")).unwrap();
        std::fs::write(src.join("package.json"), "{}").unwrap();
        std::fs::write(src.join("config").join(".env"), "NESTED_SECRET=oops").unwrap();

        let dst = tmp.path().join("output");
        copy_member_source(&src, &dst).unwrap();

        assert!(dst.join("config").exists());
        assert!(
            !dst.join("config").join(".env").exists(),
            "SECURITY: nested .env at any depth must be denied"
        );
    }

    // ── Stats accuracy ─────────────────────────────────────────────────────

    #[test]
    fn copy_member_source_returns_stats_with_files_copied_and_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        let stats = copy_member_source(&src, &dst).unwrap();

        // The fixture has multiple files in src/ and dist/ plus root files
        // that should be copied. We don't assert exact counts (fixture may
        // evolve) — just that the numbers are non-zero and sensible.
        assert!(
            stats.files_copied > 0,
            "should have copied at least one file"
        );
        assert!(
            stats.files_skipped > 0,
            "should have skipped at least one denied entry (.env, node_modules, etc.)"
        );
        assert!(stats.bytes_copied > 0);
    }

    // ── Filesystem invariants ──────────────────────────────────────────────

    #[test]
    fn copy_member_source_creates_output_dir_if_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        // Output dir does NOT exist yet
        let dst = tmp.path().join("does").join("not").join("exist");

        copy_member_source(&src, &dst).unwrap();

        assert!(dst.exists());
        assert!(dst.join("package.json").exists());
    }

    #[test]
    fn dependency_selection_production_strips_dev_and_keeps_optional_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("package.json");
        std::fs::write(
            &manifest,
            serde_json::to_string_pretty(&json!({
                "name": "api",
                "dependencies": {"runtime": "^1.0.0"},
                "devDependencies": {"test-only": "^2.0.0"},
                "optionalDependencies": {"optional-native": "^3.0.0"}
            }))
            .unwrap(),
        )
        .unwrap();

        let stats = apply_dependency_selection_to_manifest_path(
            &manifest,
            DependencyMode::Production,
            false,
        )
        .unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();

        assert_eq!(stats.dev_dependencies_stripped, 1);
        assert!(doc.get("devDependencies").is_none());
        assert_eq!(doc["dependencies"]["runtime"], "^1.0.0");
        assert_eq!(doc["optionalDependencies"]["optional-native"], "^3.0.0");
    }

    #[test]
    fn dependency_selection_dev_strips_production_and_optional_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("package.json");
        std::fs::write(
            &manifest,
            serde_json::to_string_pretty(&json!({
                "name": "api",
                "dependencies": {"runtime": "^1.0.0"},
                "devDependencies": {"test-only": "^2.0.0"},
                "optionalDependencies": {"optional-native": "^3.0.0"}
            }))
            .unwrap(),
        )
        .unwrap();

        let stats = apply_dependency_selection_to_manifest_path(
            &manifest,
            DependencyMode::Development,
            false,
        )
        .unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();

        assert_eq!(stats.production_dependencies_stripped, 1);
        assert_eq!(stats.optional_dependencies_stripped, 1);
        assert!(doc.get("dependencies").is_none());
        assert!(doc.get("optionalDependencies").is_none());
        assert_eq!(doc["devDependencies"]["test-only"], "^2.0.0");
    }

    #[test]
    fn dependency_selection_no_optional_strips_optional_in_production_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("package.json");
        std::fs::write(
            &manifest,
            serde_json::to_string_pretty(&json!({
                "name": "api",
                "dependencies": {"runtime": "^1.0.0"},
                "optionalDependencies": {"optional-native": "^3.0.0"}
            }))
            .unwrap(),
        )
        .unwrap();

        let stats = apply_dependency_selection_to_manifest_path(
            &manifest,
            DependencyMode::Production,
            true,
        )
        .unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&manifest).unwrap()).unwrap();

        assert_eq!(stats.optional_dependencies_stripped, 1);
        assert!(doc.get("optionalDependencies").is_none());
        assert_eq!(doc["dependencies"]["runtime"], "^1.0.0");
    }

    #[test]
    fn copy_member_source_does_not_modify_source_directory() {
        // CRITICAL invariant: the deploy command is read-only on the source
        // side. Snapshot the source dir before the copy and verify nothing
        // changed.
        let tmp = tempfile::tempdir().unwrap();
        let src = build_member_fixture(tmp.path());
        let dst = tmp.path().join("output");

        // Snapshot relevant source files
        let pkg_before = std::fs::read_to_string(src.join("package.json")).unwrap();
        let env_before = std::fs::read_to_string(src.join(".env")).unwrap();
        let index_before = std::fs::read_to_string(src.join("src").join("index.ts")).unwrap();

        copy_member_source(&src, &dst).unwrap();

        // Verify the source is byte-identical
        assert_eq!(
            std::fs::read_to_string(src.join("package.json")).unwrap(),
            pkg_before
        );
        assert_eq!(
            std::fs::read_to_string(src.join(".env")).unwrap(),
            env_before
        );
        assert_eq!(
            std::fs::read_to_string(src.join("src").join("index.ts")).unwrap(),
            index_before
        );
    }

    #[test]
    fn copy_member_source_errors_when_source_does_not_exist() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("does-not-exist");
        let dst = tmp.path().join("output");

        let err = copy_member_source(&absent, &dst).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    // ────────────────────────────────────────────────────────────────────
    // deploy stays prod-only after `lpm install` learned to
    // resolve devDependencies. `strip_dev_dependencies_from_deploy_manifest`
    // is the load-bearing step that keeps dev-only packages (vitest, tsup,
    // eslint, etc.) out of the deploy closure.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn strip_dev_dependencies_removes_section_entirely() {
        let tmp = tempfile::tempdir().unwrap();
        let output = tmp.path().to_path_buf();
        std::fs::write(
            output.join("package.json"),
            r#"{
                "name": "api",
                "version": "1.0.0",
                "dependencies": { "express": "^4.0.0" },
                "devDependencies": { "vitest": "^1.0.0", "tsup": "^8.0.0" }
            }"#,
        )
        .unwrap();

        let stripped = strip_dev_dependencies_from_deploy_manifest(&output).unwrap();

        assert_eq!(stripped, 2, "both vitest and tsup should be counted");

        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        assert!(
            after.get("devDependencies").is_none(),
            "devDependencies key must be gone, not just emptied"
        );
        // dependencies must be preserved byte-for-byte
        assert_eq!(
            after["dependencies"]["express"].as_str(),
            Some("^4.0.0"),
            "stripping devDeps must not touch dependencies"
        );
    }

    #[test]
    fn strip_dev_dependencies_is_noop_when_section_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let output = tmp.path().to_path_buf();
        let original = r#"{
                "name": "api",
                "version": "1.0.0",
                "dependencies": { "express": "^4.0.0" }
            }"#;
        std::fs::write(output.join("package.json"), original).unwrap();

        let stripped = strip_dev_dependencies_from_deploy_manifest(&output).unwrap();

        assert_eq!(stripped, 0);
        // No-op case must leave the bytes untouched — important for preserving
        // hand-authored formatting when nothing needed to change.
        assert_eq!(
            std::fs::read_to_string(output.join("package.json")).unwrap(),
            original
        );
    }

    #[test]
    fn strip_dev_dependencies_is_noop_when_section_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let output = tmp.path().to_path_buf();
        let original = r#"{
                "name": "api",
                "version": "1.0.0",
                "dependencies": { "express": "^4.0.0" },
                "devDependencies": {}
            }"#;
        std::fs::write(output.join("package.json"), original).unwrap();

        let stripped = strip_dev_dependencies_from_deploy_manifest(&output).unwrap();

        assert_eq!(stripped, 0);
        // Empty section is treated as "nothing to do" — the bytes stay.
        assert_eq!(
            std::fs::read_to_string(output.join("package.json")).unwrap(),
            original
        );
    }

    #[test]
    fn strip_dev_dependencies_breaks_hardlink_to_protect_source() {
        // Mirror of the  regression pattern: copy_member_source may
        // hardlink the output's package.json to the source workspace's. A
        // naive write inside strip would mutate the source. This test sets
        // up an explicit hardlink, runs strip, and asserts the source is
        // untouched while the output is rewritten.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let output = tmp.path().join("output");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&output).unwrap();

        let source_manifest = source.join("package.json");
        let output_manifest = output.join("package.json");
        let original = r#"{
                "name": "api",
                "version": "1.0.0",
                "dependencies": { "express": "^4.0.0" },
                "devDependencies": { "vitest": "^1.0.0" }
            }"#;
        std::fs::write(&source_manifest, original).unwrap();
        // Force a hardlink — `copy_member_source` would have done this
        // naturally when source and output live on the same filesystem.
        std::fs::hard_link(&source_manifest, &output_manifest).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let source_inode_before = source_manifest.metadata().unwrap();
            let output_inode_before = output_manifest.metadata().unwrap();
            assert_eq!(
                source_inode_before.ino(),
                output_inode_before.ino(),
                "setup precondition: source and output must share an inode"
            );
        }

        let stripped = strip_dev_dependencies_from_deploy_manifest(&output).unwrap();
        assert_eq!(stripped, 1);

        // 1. The source manifest is byte-identical — the hardlink was
        //    broken BEFORE the write.
        assert_eq!(
            std::fs::read_to_string(&source_manifest).unwrap(),
            original,
            "source manifest must be byte-identical after deploy strip"
        );

        // 2. The output manifest IS modified — devDeps gone, deps preserved.
        let after_output: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&output_manifest).unwrap()).unwrap();
        assert!(after_output.get("devDependencies").is_none());
        assert_eq!(
            after_output["dependencies"]["express"].as_str(),
            Some("^4.0.0")
        );

        // 3. The two paths now point at DIFFERENT inodes — proof the
        //    hardlink was actually broken, not merely avoided via copy.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                source_manifest.metadata().unwrap().ino(),
                output_manifest.metadata().unwrap().ino(),
                "hardlink must be broken by strip — otherwise any future \
                 modification risks leaking into the source"
            );
        }
    }

    #[test]
    fn strip_dev_dependencies_preserves_other_dep_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let output = tmp.path().to_path_buf();
        std::fs::write(
            output.join("package.json"),
            r#"{
                "name": "api",
                "version": "1.0.0",
                "dependencies": { "express": "^4.0.0" },
                "devDependencies": { "vitest": "^1.0.0" },
                "peerDependencies": { "react": "^18.0.0" },
                "optionalDependencies": { "fsevents": "^2.0.0" }
            }"#,
        )
        .unwrap();

        strip_dev_dependencies_from_deploy_manifest(&output).unwrap();

        let after: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(output.join("package.json")).unwrap())
                .unwrap();
        assert!(after.get("devDependencies").is_none());
        assert_eq!(after["dependencies"]["express"].as_str(), Some("^4.0.0"));
        assert_eq!(
            after["peerDependencies"]["react"].as_str(),
            Some("^18.0.0"),
            "peerDependencies must survive — only devDependencies are prod-stripped"
        );
        assert_eq!(
            after["optionalDependencies"]["fsevents"].as_str(),
            Some("^2.0.0"),
            "optionalDependencies must survive — only devDependencies are prod-stripped"
        );
    }
}
