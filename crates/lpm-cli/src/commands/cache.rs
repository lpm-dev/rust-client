//! `lpm cache` — manage ephemeral caches under `~/.lpm/cache/`.
//!
//! Phase 37 semantic flip: before this change, `lpm cache` operated on the
//! content-addressable package *store* (`~/.lpm/store/v1/`) despite the
//! name, while `~/.lpm/cache/metadata/`, `~/.lpm/cache/tasks/`, and
//! `~/.lpm/dlx-cache/` (now `~/.lpm/cache/dlx/`) were untouched. That is
//! fixed now: `lpm cache` only ever touches the cache directories, and
//! `lpm store` is the single entry point for store maintenance.
//!
//! Surface:
//!   lpm cache clean                 cleans metadata + tasks + dlx
//!   lpm cache clean metadata        cleans one subcategory
//!   lpm cache clean tasks
//!   lpm cache clean dlx
//!   lpm cache path                  prints the cache root
//!   lpm cache path metadata         prints one subcategory path
//!
//! No `--all` flag. If a user wants the store wiped too, they chain
//! `lpm cache clean && lpm store clean`. Keeping the command/directory
//! mapping one-to-one is the whole point of the rename.

use crate::output;
use lpm_common::{LpmError, LpmRoot, format_bytes, with_exclusive_lock};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const RECENT_STORE_ACTIVITY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

pub async fn run(
    action: &str,
    subcategory: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;

    match action {
        "clean" | "clear" => run_clean(&root, subcategory, json_output),
        "path" => run_path(&root, subcategory, json_output),
        other => Err(LpmError::Registry(format!(
            "unknown cache action '{other}'. Use: clean [metadata|tasks|dlx], path [metadata|tasks|dlx]"
        ))),
    }
}

// ─── clean ─────────────────────────────────────────────────────────────

fn run_clean(root: &LpmRoot, subcategory: Option<&str>, json_output: bool) -> Result<(), LpmError> {
    let targets = resolve_targets(root, subcategory)?;

    with_exclusive_lock(root.cache_clean_lock(), || {
        let mut cleaned: Vec<CleanedEntry> = Vec::new();
        for (name, dir) in &targets {
            if !dir.exists() {
                continue;
            }
            let bytes_freed = dir_size(dir).unwrap_or(0);
            std::fs::remove_dir_all(dir)?;
            cleaned.push(CleanedEntry {
                category: name,
                path: dir.clone(),
                bytes_freed,
            });
        }

        if json_output {
            emit_clean_json(&cleaned);
        } else {
            emit_clean_human(&cleaned);
        }

        // One-time notice: warn users who ran `lpm cache clean` expecting
        // the pre-phase-37 store-wipe behavior. Only fires when (a) the
        // command was invoked without a subcategory (the blanket form is
        // what matches the old workflow), (b) stdout is not JSON (the
        // notice goes to stderr either way, but we keep machine output
        // clean), and (c) the store contains recently-touched packages —
        // i.e. the user actually had store state the old command would
        // have cleared. The marker file suppresses the notice on
        // subsequent runs even if the conditions stay true.
        if subcategory.is_none() && !json_output {
            maybe_show_semantic_change_notice(root);
        }

        Ok(())
    })
}

fn resolve_targets(
    root: &LpmRoot,
    subcategory: Option<&str>,
) -> Result<Vec<(&'static str, PathBuf)>, LpmError> {
    Ok(match subcategory {
        None => vec![
            ("metadata", root.cache_metadata()),
            ("tasks", root.cache_tasks()),
            ("dlx", root.cache_dlx()),
        ],
        Some("metadata") => vec![("metadata", root.cache_metadata())],
        Some("tasks") => vec![("tasks", root.cache_tasks())],
        Some("dlx") => vec![("dlx", root.cache_dlx())],
        Some(other) => {
            return Err(LpmError::Registry(format!(
                "unknown cache subcategory '{other}'. Use: metadata, tasks, dlx"
            )));
        }
    })
}

struct CleanedEntry {
    category: &'static str,
    path: PathBuf,
    bytes_freed: u64,
}

fn emit_clean_json(cleaned: &[CleanedEntry]) {
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
    let total: u64 = cleaned.iter().map(|c| c.bytes_freed).sum();
    let json = serde_json::json!({
        "success": true,
        "cleaned": entries,
        "total_bytes_freed": total,
        "total_freed": format_bytes(total),
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

fn emit_clean_human(cleaned: &[CleanedEntry]) {
    if cleaned.is_empty() {
        output::info("Cache is already empty");
        return;
    }
    for c in cleaned {
        output::success(&format!(
            "Cleared {} cache ({})",
            c.category,
            format_bytes(c.bytes_freed)
        ));
    }
    let total: u64 = cleaned.iter().map(|c| c.bytes_freed).sum();
    if cleaned.len() > 1 {
        output::info(&format!("Total freed: {}", format_bytes(total)));
    }
}

// ─── path ──────────────────────────────────────────────────────────────

fn run_path(root: &LpmRoot, subcategory: Option<&str>, json_output: bool) -> Result<(), LpmError> {
    let path = match subcategory {
        None => root.cache_root(),
        Some("metadata") => root.cache_metadata(),
        Some("tasks") => root.cache_tasks(),
        Some("dlx") => root.cache_dlx(),
        Some(other) => {
            return Err(LpmError::Registry(format!(
                "unknown cache subcategory '{other}'. Use: metadata, tasks, dlx"
            )));
        }
    };
    if json_output {
        let json = serde_json::json!({
            "success": true,
            "path": path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!("{}", path.display());
    }
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────

/// Recursively compute the on-disk size of a directory in bytes.
/// Exposed to sibling command modules so `lpm store clean` can report the
/// freed size without duplicating the walker.
pub(crate) fn dir_size(path: &Path) -> std::io::Result<u64> {
    let mut total: u64 = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            total = total.saturating_add(dir_size(&entry.path())?);
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
fn maybe_show_semantic_change_notice(root: &LpmRoot) {
    let marker = root.cache_clean_notice_marker();
    if marker.exists() {
        return;
    }
    if !store_has_recent_children(&root.store_v1(), RECENT_STORE_ACTIVITY_WINDOW) {
        return;
    }
    eprintln!();
    eprintln!("Note: `lpm cache clean` now cleans metadata, task, and dlx caches only.");
    eprintln!("The package store was left untouched. Use `lpm store gc` for reference-aware");
    eprintln!("cleanup, or `lpm store clean` to wipe the store.");
    eprintln!();
    let _ = std::fs::write(&marker, b"");
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
        if now
            .duration_since(mtime)
            .map(|age| age < max_age)
            .unwrap_or(false)
        {
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

    fn populate(dir: &Path, files: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        for name in files {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
    }

    #[test]
    fn resolve_targets_no_subcategory_returns_all_three() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        let targets = resolve_targets(&root, None).unwrap();
        let names: Vec<&str> = targets.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["metadata", "tasks", "dlx"]);
    }

    #[test]
    fn resolve_targets_subcategory_returns_one() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        for sub in ["metadata", "tasks", "dlx"] {
            let targets = resolve_targets(&root, Some(sub)).unwrap();
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].0, sub);
        }
    }

    #[test]
    fn resolve_targets_unknown_subcategory_errors() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);
        let err = resolve_targets(&root, Some("bogus")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown cache subcategory"), "got: {msg}");
    }

    #[tokio::test]
    async fn clean_without_subcategory_clears_all_cache_dirs_only() {
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);

        populate(&root.cache_metadata(), &["a.json"]);
        populate(&root.cache_tasks(), &["b.json"]);
        populate(&root.cache_dlx().join("hash1"), &["package.json"]);

        // Plant store state to prove we DON'T touch it.
        populate(&root.store_v1().join("react@19.0.0"), &["index.js"]);

        // Drive the command via its public surface.
        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        run("clean", None, true).await.unwrap();
        unsafe {
            std::env::remove_var("LPM_HOME");
        }

        assert!(!root.cache_metadata().exists(), "metadata should be gone");
        assert!(!root.cache_tasks().exists(), "tasks should be gone");
        assert!(!root.cache_dlx().exists(), "dlx should be gone");
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

        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        run("clean", Some("metadata"), true).await.unwrap();
        unsafe {
            std::env::remove_var("LPM_HOME");
        }

        assert!(!root.cache_metadata().exists());
        assert!(root.cache_tasks().join("b.json").exists());
        assert!(root.cache_dlx().join("hash1").join("package.json").exists());
    }

    #[tokio::test]
    async fn clean_does_not_touch_store_even_without_subcategory() {
        // Dedicated regression test for the semantic flip — the whole
        // point of phase 37's cache/store rename is that `cache clean`
        // must never reach into the store, regardless of flags.
        let tmp = TempDir::new().unwrap();
        let root = setup(&tmp);

        populate(&root.cache_metadata(), &["a.json"]);
        populate(&root.store_v1().join("lodash@4.17.21"), &["index.js"]);
        populate(&root.store_v1().join("react@19.0.0"), &["index.js"]);

        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        run("clean", None, true).await.unwrap();
        unsafe {
            std::env::remove_var("LPM_HOME");
        }

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

        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        // Human-readable path triggers the notice; JSON path deliberately
        // does not (see emit_clean_json callers). This test exercises the
        // human branch.
        run("clean", None, false).await.unwrap();
        unsafe {
            std::env::remove_var("LPM_HOME");
        }

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

        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        run("clean", None, false).await.unwrap();
        // Capture marker mtime; second run must not rewrite it.
        let first_mtime = std::fs::metadata(root.cache_clean_notice_marker())
            .unwrap()
            .modified()
            .unwrap();

        populate(&root.cache_metadata(), &["a.json"]);
        run("clean", None, false).await.unwrap();
        unsafe {
            std::env::remove_var("LPM_HOME");
        }

        let second_mtime = std::fs::metadata(root.cache_clean_notice_marker())
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(first_mtime, second_mtime, "marker must not be rewritten");
    }

    #[tokio::test]
    async fn path_action_prints_cache_root_by_default() {
        let tmp = TempDir::new().unwrap();
        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        // We can't easily capture stdout from inside a tokio test without
        // pulling in a redirect harness; we assert success + sane behavior
        // and trust the emit_* helpers. The JSON path is deterministic.
        run("path", None, true).await.unwrap();
        run("path", Some("metadata"), true).await.unwrap();
        run("path", Some("tasks"), true).await.unwrap();
        run("path", Some("dlx"), true).await.unwrap();
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
    }

    #[tokio::test]
    async fn unknown_action_errors() {
        let tmp = TempDir::new().unwrap();
        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        let err = run("bogus", None, true).await.unwrap_err();
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
        let msg = format!("{err}");
        assert!(msg.contains("unknown cache action"), "got: {msg}");
    }
}
