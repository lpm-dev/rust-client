//! `lpm cache` — manage ephemeral caches under `~/.lpm/cache/`.
//!
//! semantic flip: before this change, `lpm cache` operated on the
//! content-addressable package *store* (`~/.lpm/store/v1/`) despite the
//! name, while metadata, task, and runner caches were untouched. That is
//! fixed now: `lpm cache` only ever touches cache directories, and `lpm
//! store` is the single entry point for store maintenance.
//!
//! Surface:
//!   lpm cache clean                 cleans metadata + tasks + dlx + mcp
//!   lpm cache clean metadata        cleans one subcategory
//!   lpm cache clean tasks
//!   lpm cache clean dlx
//!   lpm cache clean mcp
//!   lpm cache path                  prints the cache root
//!   lpm cache path metadata         prints one subcategory path
//!   lpm cache status                reports local task cache usage + remote status
//!
//! No `--all` flag. If a user wants the store wiped too, they chain
//! `lpm cache clean && lpm store clean`. Keeping the command/directory
//! mapping one-to-one is the whole point of the rename.

use crate::install_ui;
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::Dir;
use lpm_common::{
    LpmError, LpmRoot, format_bytes, try_acquire_capability_exclusive_lock,
    with_capability_exclusive_lock,
};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

const RECENT_STORE_ACTIVITY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, clap::Subcommand)]
pub(crate) enum CacheCmd {
    /// Remove ephemeral cache data.
    #[command(alias = "clear")]
    Clean {
        /// Cache category. Omit it to clean every category.
        #[arg(value_name = "CATEGORY")]
        category: Option<CacheCategory>,
    },

    /// Print the cache root or one category path.
    Path {
        /// Cache category. Omit it to print the cache root.
        #[arg(value_name = "CATEGORY")]
        category: Option<CacheCategory>,
    },

    /// Report local task-cache usage and remote-cache status.
    Status,

    /// Find package-store entries that registered projects no longer use.
    Prune {
        /// Remove eligible entries. Omit it for a dry-run.
        #[arg(long)]
        apply: bool,

        /// Restrict pruning to entries older than this duration (`30d`, `24h`).
        #[arg(long)]
        max_age: Option<String>,

        /// Use only this project's `node_modules` as the root set.
        #[arg(long, value_name = "PATH")]
        project: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub(crate) enum CacheCategory {
    Metadata,
    Tasks,
    Dlx,
    Mcp,
}

impl CacheCategory {
    fn name(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Tasks => "tasks",
            Self::Dlx => "dlx",
            Self::Mcp => "mcp",
        }
    }

    fn path(self, root: &LpmRoot) -> PathBuf {
        match self {
            Self::Metadata => root.cache_metadata(),
            Self::Tasks => root.cache_tasks(),
            Self::Dlx => root.cache_dlx(),
            Self::Mcp => root.cache_mcp(),
        }
    }
}

/// Flags shared by every `lpm cache <action>` call site so the
/// dispatcher signature stays stable across actions. `clean` and `path`
/// ignore every field; `prune` reads them.
#[derive(Debug, Clone, Default)]
pub struct PruneFlags<'a> {
    /// Default `false` (dry-run); `true` actually removes orphans
    /// AND sweeps deferred global-install tombstones.
    pub apply: bool,
    /// Filter by `last_referenced_at` age (e.g., `30d`, `24h`).
    pub max_age: Option<&'a str>,
    /// Manual repair mode — use ONLY this project's `node_modules/`
    /// as the root set; ignore the registry.
    pub project: Option<&'a str>,
}

pub async fn run(
    action: CacheCmd,
    json_output: bool,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;

    match action {
        CacheCmd::Clean { category } => run_clean(&root, category, json_output),
        CacheCmd::Path { category } => {
            run_path(&root, category, json_output);
            Ok(())
        }
        CacheCmd::Prune {
            apply,
            max_age,
            project,
        } => {
            super::cache_prune::run(
                &root,
                json_output,
                PruneFlags {
                    apply,
                    max_age: max_age.as_deref(),
                    project: project.as_deref(),
                },
            )
            .await
        }
        CacheCmd::Status => run_status(json_output, session),
    }
}

// ─── clean ─────────────────────────────────────────────────────────────

fn run_clean(
    root: &LpmRoot,
    category: Option<CacheCategory>,
    json_output: bool,
) -> Result<(), LpmError> {
    let targets = resolve_targets(root, category);
    let open_roots = open_cache_roots(root)?;

    with_capability_exclusive_lock(
        &open_roots.cache,
        &root.cache_root(),
        OsStr::new(".clean.lock"),
        || {
            let mut cleaned: Vec<CleanedEntry> = Vec::new();
            let mut skipped: Vec<SkippedEntry> = Vec::new();
            for (name, dir) in &targets {
                let mcp_lock = if *name == "mcp" {
                    match try_acquire_capability_exclusive_lock(
                        &open_roots.cache,
                        &root.cache_root(),
                        OsStr::new(".mcp.lock"),
                    )? {
                        Some(lock) => Some(lock),
                        None if matches!(category, Some(CacheCategory::Mcp)) => {
                            return Err(LpmError::Registry(
                                "MCP cache is in use; stop active MCP server sessions and retry"
                                    .into(),
                            ));
                        }
                        None => {
                            skipped.push(SkippedEntry {
                                category: name,
                                path: dir.clone(),
                                reason: "in use",
                            });
                            continue;
                        }
                    }
                } else {
                    None
                };
                let Some(bytes_freed) =
                    remove_open_entry_with_size(&open_roots.cache, OsStr::new(name))?
                else {
                    continue;
                };
                drop(mcp_lock);
                cleaned.push(CleanedEntry {
                    category: name,
                    path: dir.clone(),
                    bytes_freed,
                });
            }

            if json_output {
                emit_clean_json(&cleaned, &skipped);
            } else {
                emit_clean_human(&cleaned, &skipped);
            }

            // One-time notice: warn users who ran `lpm cache clean` expecting
            // the older store-wipe behavior. Only fires when the blanket form
            // was invoked, stdout is not JSON, and the store contains recently
            // touched packages. The marker file suppresses later repeats.
            if category.is_none() && !json_output {
                maybe_show_semantic_change_notice(root, &open_roots.lpm);
            }

            Ok(())
        },
    )
}

struct OpenCacheRoots {
    lpm: Dir,
    cache: Dir,
}

fn open_cache_roots(root: &LpmRoot) -> Result<OpenCacheRoots, LpmError> {
    let root_path = root.root();
    let parent_path = root_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent_path)?;
    let parent = Dir::open_ambient_dir(parent_path, cap_std::ambient_authority())?;
    let root_name = root_path.file_name().ok_or_else(|| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("LPM root has no final component: {}", root_path.display()),
        ))
    })?;
    let lpm = open_or_create_directory(&parent, root_name, root_path, "LPM root")?;
    let cache_path = root.cache_root();
    let cache = open_or_create_directory(&lpm, OsStr::new("cache"), &cache_path, "cache root")?;
    restrict_cache_directory(&cache)?;
    Ok(OpenCacheRoots { lpm, cache })
}

pub(super) fn open_or_create_directory(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
    label: &str,
) -> Result<Dir, LpmError> {
    match parent.open_dir_nofollow(name) {
        Ok(directory) => validate_open_directory(directory, display, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match parent.create_dir(name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            let directory = parent.open_dir_nofollow(name).map_err(|error| {
                LpmError::Io(std::io::Error::new(
                    error.kind(),
                    format!(
                        "refusing {label} that is not a real directory at {}: {error}",
                        display.display()
                    ),
                ))
            })?;
            validate_open_directory(directory, display, label)
        }
        Err(error) => Err(LpmError::Io(std::io::Error::new(
            error.kind(),
            format!(
                "refusing {label} that is not a real directory at {}: {error}",
                display.display()
            ),
        ))),
    }
}

fn validate_open_directory(directory: Dir, display: &Path, label: &str) -> Result<Dir, LpmError> {
    let metadata = directory.dir_metadata()?;
    if !metadata.is_dir() || cap_metadata_is_link_or_reparse(&metadata) {
        return Err(LpmError::Io(std::io::Error::other(format!(
            "refusing {label} that is not a real directory at {}",
            display.display()
        ))));
    }
    Ok(directory)
}

#[cfg(unix)]
fn restrict_cache_directory(directory: &Dir) -> Result<(), LpmError> {
    use cap_std::fs::PermissionsExt as _;

    directory.set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_cache_directory(_directory: &Dir) -> Result<(), LpmError> {
    Ok(())
}

pub(super) fn remove_open_entry_with_size(
    parent: &Dir,
    name: &OsStr,
) -> Result<Option<u64>, LpmError> {
    let metadata = match parent.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() && !cap_metadata_is_link_or_reparse(&metadata) {
        let directory = parent.open_dir_nofollow(name)?;
        let bytes = clear_open_directory(&directory)?;
        drop(directory);
        match parent.remove_dir(name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Some(bytes))
    } else {
        let bytes = if metadata.is_file() && !cap_metadata_is_link_or_reparse(&metadata) {
            metadata.len()
        } else {
            0
        };
        match parent.remove_file_or_symlink(name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Some(bytes))
    }
}

fn clear_open_directory(directory: &Dir) -> Result<u64, LpmError> {
    let mut bytes = 0u64;
    for entry in directory.entries()? {
        let entry = entry?;
        if let Some(removed) = remove_open_entry_with_size(directory, &entry.file_name())? {
            bytes = bytes.saturating_add(removed);
        }
    }
    Ok(bytes)
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

fn resolve_targets(
    root: &LpmRoot,
    category: Option<CacheCategory>,
) -> Vec<(&'static str, PathBuf)> {
    match category {
        None => vec![
            ("metadata", root.cache_metadata()),
            ("tasks", root.cache_tasks()),
            ("dlx", root.cache_dlx()),
            ("mcp", root.cache_mcp()),
        ],
        Some(category) => vec![(category.name(), category.path(root))],
    }
}

struct CleanedEntry {
    category: &'static str,
    path: PathBuf,
    bytes_freed: u64,
}

struct SkippedEntry {
    category: &'static str,
    path: PathBuf,
    reason: &'static str,
}

fn emit_clean_json(cleaned: &[CleanedEntry], skipped: &[SkippedEntry]) {
    let entries: Vec<_> = cleaned
        .iter()
        .map(|c| {
            serde_json::json!({
                "category": c.category,
                "path": c.path.display().to_string(),
                "bytes_freed": c.bytes_freed,
                "freed": format_bytes(c.bytes_freed),
            })
        })
        .collect();
    let skipped_entries: Vec<_> = skipped
        .iter()
        .map(|entry| {
            serde_json::json!({
                "category": entry.category,
                "path": entry.path.display().to_string(),
                "reason": entry.reason,
            })
        })
        .collect();
    let total: u64 = cleaned.iter().map(|c| c.bytes_freed).sum();
    let json = serde_json::json!({
        "success": true,
        "cleaned": entries,
        "skipped": skipped_entries,
        "total_bytes_freed": total,
        "total_freed": format_bytes(total),
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

fn emit_clean_human(cleaned: &[CleanedEntry], skipped: &[SkippedEntry]) {
    let total: u64 = cleaned.iter().map(|c| c.bytes_freed).sum();
    if cleaned.is_empty() {
        if skipped.is_empty() {
            install_ui::done("Cache is already empty");
        }
    } else if skipped.is_empty() && total == 0 {
        install_ui::done("Cache is already empty");
    } else if cleaned.len() == 1 {
        let entry = &cleaned[0];
        install_ui::done_untrusted(&format!(
            "Cleared {} cache · freed {}",
            entry.category,
            format_bytes(total)
        ));
    } else {
        install_ui::done_untrusted(&format!(
            "Cleared {} cache directories · freed {}",
            cleaned.len(),
            format_bytes(total)
        ));
    }
    for entry in skipped {
        install_ui::warn_untrusted(&format!(
            "{} cache was not cleared because it is {}",
            entry.category, entry.reason
        ));
    }
}

// ─── path ──────────────────────────────────────────────────────────────

fn run_path(root: &LpmRoot, category: Option<CacheCategory>, json_output: bool) {
    let path = match category {
        None => root.cache_root(),
        Some(category) => category.path(root),
    };
    if json_output {
        let json = serde_json::json!({
            "success": true,
            "path": path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!(
            "{}",
            crate::install_ui::terminal_line!("{}", path.display().to_string())
        );
    }
}

fn run_status(
    json_output: bool,
    session: Option<Arc<lpm_auth::SessionManager>>,
) -> Result<(), LpmError> {
    let cwd = std::env::current_dir()?;
    let status = super::remote_cache::status_for_project(&cwd, session)?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&super::remote_cache::cache_status_json(&status)).unwrap()
        );
    } else {
        super::remote_cache::print_cache_status_human(&status);
    }
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────

/// Recursively compute the on-disk size of a directory in bytes.
/// Exposed to sibling command modules so `lpm store clean` can report the
/// freed size without duplicating the walker.
pub(crate) fn dir_size(path: &Path) -> std::io::Result<u64> {
    let root_metadata = std::fs::symlink_metadata(path)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("not a real directory: {}", path.display()),
        ));
    }
    dir_size_inner(path)
}

fn dir_size_inner(path: &Path) -> std::io::Result<u64> {
    let mut total: u64 = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            total = total.saturating_add(dir_size_inner(&entry.path())?);
        } else if ft.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        }
        // Symlinks are not followed; their on-disk size is the link
        // inode's own footprint, which is negligible and not interesting
        // to display.
    }
    Ok(total)
}

/// Emit the one-time semantic-change banner if appropriate. Best-effort:
/// any I/O error during marker creation is swallowed because the notice
/// is purely advisory — failing to suppress it next time is a minor
/// annoyance, not a correctness issue.
fn maybe_show_semantic_change_notice(root: &LpmRoot, lpm: &Dir) {
    let marker = root.cache_clean_notice_marker();
    let Some(marker_name) = marker.file_name() else {
        return;
    };
    if lpm.symlink_metadata(marker_name).is_ok() {
        return;
    }
    if !store_has_recent_children(&root.store_v1(), RECENT_STORE_ACTIVITY_WINDOW) {
        return;
    }
    emit_semantic_change_notice();
    let mut options = cap_std::fs::OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let _ = lpm.open_with(marker_name, &options);
}

fn emit_semantic_change_notice() {
    install_ui::warn("cache clean left the package store untouched");
    for line in semantic_change_notice_details() {
        install_ui::detail_line(line);
    }
}

fn semantic_change_notice_details() -> Vec<install_ui::TerminalLine> {
    vec![
        crate::install_ui::terminal_line!(
            "  {} `lpm cache clean` now cleans metadata, task, dlx, and MCP caches only.",
            install_ui::dim("note")
        ),
        crate::install_ui::terminal_line!(
            "  {} Use {} for reference-aware cleanup.",
            install_ui::dim("command"),
            install_ui::yellow("lpm cache prune --apply")
        ),
        crate::install_ui::terminal_line!(
            "  {} Use {} to wipe the store.",
            install_ui::dim("command"),
            install_ui::yellow("lpm store clean")
        ),
    ]
}

/// True when `dir` has at least one direct child modified within `max_age`.
/// Used to detect whether the store has been touched recently enough that
/// the semantic-change notice is worth emitting. Absent dir / IO errors
/// both map to `false` — no recent activity by our lights.
fn store_has_recent_children(dir: &Path, max_age: Duration) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(mtime) = meta.modified() else { continue };
        if now.duration_since(mtime).is_ok_and(|age| age < max_age) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup(tmp: &TempDir) -> LpmRoot {
        LpmRoot::from_dir(tmp.path())
    }

    fn scoped_lpm_home(path: &Path) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::set([("LPM_HOME", path.as_os_str().to_owned())])
    }

    fn populate(dir: &Path, files: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        for name in files {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
    }

    #[test]
    fn resolve_targets_no_subcategory_returns_all_four() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        let targets = resolve_targets(&root, None);
        let names: Vec<&str> = targets.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["metadata", "tasks", "dlx", "mcp"]);
    }

    #[test]
    fn resolve_targets_subcategory_returns_one() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        for (category, name) in [
            (CacheCategory::Metadata, "metadata"),
            (CacheCategory::Tasks, "tasks"),
            (CacheCategory::Dlx, "dlx"),
            (CacheCategory::Mcp, "mcp"),
        ] {
            let targets = resolve_targets(&root, Some(category));
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].0, name);
        }
    }

    #[test]
    fn semantic_change_notice_details_use_slim_body_roles() {
        let details = semantic_change_notice_details();
        let joined = details
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let joined = console::strip_ansi_codes(&joined).into_owned();

        assert!(
            joined.contains(
                "note `lpm cache clean` now cleans metadata, task, dlx, and MCP caches only."
            ),
            "notice should explain the new cache-clean scope: {joined}"
        );
        assert!(
            joined.contains("command Use lpm cache prune --apply")
                && joined.contains("command Use lpm store clean"),
            "notice should include command detail rows: {joined}"
        );
    }

    #[tokio::test]
    async fn clean_without_subcategory_clears_all_cache_dirs_only() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);

        populate(&root.cache_metadata(), &["a.json"]);
        populate(&root.cache_tasks(), &["b.json"]);
        populate(&root.cache_dlx().join("hash1"), &["package.json"]);
        populate(&root.cache_mcp().join("runtime"), &["package.json"]);

        // Plant store state to prove we DON'T touch it.
        populate(&root.store_v1().join("react@19.0.0"), &["index.js"]);

        // Drive the command via its public surface.
        let _env = scoped_lpm_home(tmp.path());
        run(CacheCmd::Clean { category: None }, true, None)
            .await
            .unwrap();

        assert!(!root.cache_metadata().exists(), "metadata should be gone");
        assert!(!root.cache_tasks().exists(), "tasks should be gone");
        assert!(!root.cache_dlx().exists(), "dlx should be gone");
        assert!(!root.cache_mcp().exists(), "mcp should be gone");
        assert!(
            root.store_v1().join("react@19.0.0").exists(),
            "store must be untouched"
        );
    }

    #[tokio::test]
    async fn clean_with_subcategory_touches_only_that_subcategory() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);

        populate(&root.cache_metadata(), &["a.json"]);
        populate(&root.cache_tasks(), &["b.json"]);
        populate(&root.cache_dlx().join("hash1"), &["package.json"]);
        populate(&root.cache_mcp().join("runtime"), &["package.json"]);

        let _env = scoped_lpm_home(tmp.path());
        run(
            CacheCmd::Clean {
                category: Some(CacheCategory::Metadata),
            },
            true,
            None,
        )
        .await
        .unwrap();

        assert!(!root.cache_metadata().exists());
        assert!(root.cache_tasks().join("b.json").exists());
        assert!(root.cache_dlx().join("hash1").join("package.json").exists());
        assert!(root.cache_mcp().join("runtime/package.json").exists());
    }

    #[tokio::test]
    async fn clean_mcp_refuses_to_delete_an_in_use_runtime() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        populate(&root.cache_mcp().join("runtime"), &["package.json"]);
        let lock_path = root.cache_mcp_lock();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            lpm_common::with_shared_lock(lock_path, || {
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok::<_, LpmError>(())
            })
        });
        held_rx.recv().unwrap();

        let _env = scoped_lpm_home(tmp.path());
        let error = run(
            CacheCmd::Clean {
                category: Some(CacheCategory::Mcp),
            },
            true,
            None,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("in use"));
        assert!(root.cache_mcp().join("runtime/package.json").exists());

        release_tx.send(()).unwrap();
        holder.join().unwrap().unwrap();
    }

    #[tokio::test]
    async fn clean_does_not_touch_store_even_without_subcategory() {
        // `cache clean` must never reach into the store, regardless of flags.
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);

        populate(&root.cache_metadata(), &["a.json"]);
        populate(&root.store_v1().join("lodash@4.17.21"), &["index.js"]);
        populate(&root.store_v1().join("react@19.0.0"), &["index.js"]);

        let _env = scoped_lpm_home(tmp.path());
        run(CacheCmd::Clean { category: None }, true, None)
            .await
            .unwrap();

        assert!(!root.cache_metadata().exists());
        assert!(root.store_v1().join("lodash@4.17.21").exists());
        assert!(root.store_v1().join("react@19.0.0").exists());
    }

    #[test]
    fn store_has_recent_children_detects_recent_mtime() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        populate(&root.store_v1().join("pkg@1.0.0"), &["index.js"]);
        assert!(store_has_recent_children(
            &root.store_v1(),
            Duration::from_secs(3600)
        ));
    }

    #[test]
    fn store_has_recent_children_returns_false_for_missing_dir() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        assert!(!store_has_recent_children(
            &root.store_v1(),
            Duration::from_secs(3600)
        ));
    }

    #[tokio::test]
    async fn banner_writes_marker_on_first_cache_clean_with_store_activity() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        populate(&root.store_v1().join("pkg@1.0.0"), &["index.js"]);
        populate(&root.cache_metadata(), &["a.json"]);

        let _env = scoped_lpm_home(tmp.path());
        // Human-readable path triggers the notice; JSON path deliberately
        // does not (see emit_clean_json callers). This test exercises the
        // human branch.
        run(CacheCmd::Clean { category: None }, false, None)
            .await
            .unwrap();

        assert!(
            root.cache_clean_notice_marker().exists(),
            "marker should be created after first notice fires"
        );
    }

    #[tokio::test]
    async fn banner_is_idempotent_second_run_noop() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        populate(&root.store_v1().join("pkg@1.0.0"), &["index.js"]);
        populate(&root.cache_metadata(), &["a.json"]);

        let _env = scoped_lpm_home(tmp.path());
        run(CacheCmd::Clean { category: None }, false, None)
            .await
            .unwrap();
        // Capture marker mtime; second run must not rewrite it.
        let first_mtime = std::fs::metadata(root.cache_clean_notice_marker())
            .unwrap()
            .modified()
            .unwrap();

        populate(&root.cache_metadata(), &["a.json"]);
        run(CacheCmd::Clean { category: None }, false, None)
            .await
            .unwrap();

        let second_mtime = std::fs::metadata(root.cache_clean_notice_marker())
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(first_mtime, second_mtime, "marker must not be rewritten");
    }

    #[tokio::test]
    async fn path_action_prints_cache_root_by_default() {
        let tmp = TempDir::new().unwrap();
        let _env = scoped_lpm_home(tmp.path());
        // We can't easily capture stdout from inside a tokio test without
        // pulling in a redirect harness; we assert success + sane behavior
        // and trust the emit_* helpers. The JSON path is deterministic.
        run(CacheCmd::Path { category: None }, true, None)
            .await
            .unwrap();
        run(
            CacheCmd::Path {
                category: Some(CacheCategory::Metadata),
            },
            true,
            None,
        )
        .await
        .unwrap();
        run(
            CacheCmd::Path {
                category: Some(CacheCategory::Tasks),
            },
            true,
            None,
        )
        .await
        .unwrap();
        run(
            CacheCmd::Path {
                category: Some(CacheCategory::Dlx),
            },
            true,
            None,
        )
        .await
        .unwrap();
        run(
            CacheCmd::Path {
                category: Some(CacheCategory::Mcp),
            },
            true,
            None,
        )
        .await
        .unwrap();
    }
}
