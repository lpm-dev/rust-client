//! `lpm cache prune` — implementation.
//!
//! Walks the v2 virtual store at `~/.lpm/store/v2/{links,objects}/` and
//! removes entries no longer reachable from any registered project's
//! `node_modules/` symlink graph. Per-mode behavior:
//!
//! - **Default (registry-backed):** read
//!   `~/.lpm/known-projects.json`, drop entries pointing at deleted
//!   project paths, walk every surviving project's `node_modules/` to
//!   collect root graph-keys, BFS through `LinkMeta.deps[].target_graph_key`
//!   to mark all reachable graph-keys, and treat every other
//!   `links/<*>/` entry as an orphan. Object orphans are computed
//!   separately by joining each surviving link's `LinkMeta.object_path`
//!   tail with the names under `objects/`.
//!
//! - **`--project <path>` (manual repair):** skip the registry, walk
//!   only the supplied project. Useful after a corrupted registry or
//!   a machine restore where the registry doesn't reflect actual
//!   project state.
//!
//! - **`--max-age <duration>`:** further restrict pruning to entries
//!   whose `last_referenced_at` is older than the supplied duration.
//!   Treat fresh entries as live even when unreachable from any
//!   registered project — the registry might be stale and the entry
//!   might be in-use by an unrecorded project.
//!
//! - **`--apply`:** actually delete orphan entries AND sweep any
//!   pending global-install tombstones (deferred deletion roots from
//!   prior `lpm uninstall -g` runs that couldn't delete inline).
//!   Default is dry-run.
//!
//! ## Safety rails (preplan)
//!
//! - Canonicalized paths in the registry — symlink-cwd quirks don't
//!   accumulate aliased entries.
//! - Atomic registry rewrites via `<path>.tmp.<pid>` → rename in
//!   [`lpm_common::known_projects::write`].
//! - `last_seen` tracking on every install registration so future
//!   registry-GC workflows have a basis to filter on.
//! - Silent drop on missing project paths during the registry walk.
//! - Tombstone-only degraded mode when the registry is unusable
//!   (missing, malformed JSON, schema mismatch, or unreadable) AND no
//!   `--project` is supplied. Orphan detection is skipped; the
//!   tombstone sweep still runs under `--apply`. Treating an unusable
//!   registry as "no recorded projects" instead of refusing to walk
//!   would mark every link entry as orphaned and wipe the live store
//!   on the next apply — the degraded path is the safety contract.

use crate::output;
use chrono::{Duration as ChronoDuration, Utc};
use lpm_common::{LpmError, LpmRoot, known_projects, with_exclusive_lock, with_shared_lock};
use lpm_store::v2::Store as V2Store;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::cache::PruneFlags;

/// Outcome of a prune walk. Used by the human + JSON emitters; tests
/// also assert against this shape directly so the algorithm can be
/// unit-tested without spawning the CLI.
#[derive(Debug, Clone, Default)]
pub struct PruneSummary {
    /// `true` iff the walk ran in `--apply` mode and orphans were
    /// actually deleted; `false` for dry-run.
    pub applied: bool,
    /// Number of registered projects whose `node_modules/` was walked.
    /// Always `1` in `--project` mode.
    pub projects_walked: usize,
    /// Number of stale registry entries dropped during the walk.
    /// `0` in `--project` mode (registry untouched).
    pub registry_entries_dropped: usize,
    /// `links/<key>/` entries on disk before the walk.
    pub link_entries_total: usize,
    /// Graph-keys marked as reachable from some project's roots.
    pub link_entries_reachable: usize,
    /// Orphan link entries — pruneable per the algorithm.
    pub link_entries_orphaned: Vec<PathBuf>,
    /// `objects/<sri>/` entries on disk before the walk.
    pub object_entries_total: usize,
    /// Object SRIs referenced by some surviving link entry's sidecar.
    pub object_entries_reachable: usize,
    /// Orphan objects — pruneable per the algorithm.
    pub object_entries_orphaned: Vec<PathBuf>,
    /// Total bytes that would be / were freed by deleting orphans.
    /// Sum of `link_entries_orphaned` + `object_entries_orphaned`
    /// directory sizes.
    pub bytes_freed_or_eligible: u64,
    /// Number of pending global-install tombstones (deferred-uninstall
    /// roots from `lpm uninstall -g`) counted at preview time. Both
    /// dry-run and `--apply` populate this — it represents the count
    /// the sweep WILL operate on.
    pub tombstones_pending: usize,
    /// Tombstones successfully swept under `--apply`. Zero in dry-run.
    pub tombstones_swept: usize,
    /// Tombstones whose on-disk delete failed under `--apply` (e.g.
    /// Windows sharing violation, perms). Stays in the global manifest
    /// for the next sweep to retry.
    pub tombstones_retained: Vec<lpm_global::SweepFailure>,
    /// Bytes freed across successful tombstone deletes under `--apply`.
    pub tombstone_bytes_freed: u64,
    /// `true` when the project registry is missing AND no explicit
    /// `--project` was passed. In this state we have no roots, so
    /// orphan detection is unsafe (every link entry would look
    /// unreachable). The orphan walk is skipped, but `--apply` still
    /// runs the tombstone sweep — `lpm uninstall -g`'s deferred
    /// cleanup must remain reachable without a populated registry.
    pub registry_missing: bool,
    /// `true` when the project registry exists but is corrupt
    /// (malformed JSON, schema mismatch, or unreadable). Same
    /// orphan-walk-skipped behavior as [`Self::registry_missing`] —
    /// treating a corrupt registry as an empty root set would wipe
    /// the live store on `--apply`. Surfaced as a distinct field
    /// (vs. folding into `registry_missing`) so the human + JSON
    /// emitters can produce an actionable corruption warning instead
    /// of "no registry yet" which would mislead the user.
    pub registry_corrupt: bool,
    /// Human-readable description of why the registry was rejected,
    /// populated alongside [`Self::registry_corrupt`]. Empty on the
    /// healthy and missing-but-not-corrupt paths.
    pub registry_corrupt_reason: String,
}

/// Entry point for the CLI dispatcher. Resolves the v2 store + flags,
/// runs the algorithm under the store reader/writer lock, and emits
/// human or JSON output.
///
/// Locking. Coordinate with concurrent installs / audits / queries
/// through the store reader/writer lock at `~/.lpm/store/.gc.lock`.
/// Dry-run only reads the store + sidecars + project registry, so it
/// takes the **shared** half. `--apply` mutates the store (rm orphans,
/// sweep tombstones) and takes the **exclusive** half — it queues
/// behind in-flight readers and blocks new readers until the apply
/// finishes. The locking model is documented at
/// [`lpm store` — Locking model](https://cli.lpm.dev/docs/infra/store#locking-model).
pub async fn run(root: &LpmRoot, json_output: bool, flags: PruneFlags<'_>) -> Result<(), LpmError> {
    let v2_store = V2Store::from_lpm_root(root);
    let max_age = match flags.max_age {
        Some(s) => Some(parse_duration(s)?),
        None => None,
    };

    let summary = if flags.apply {
        with_exclusive_lock(root.store_lock(), || {
            run_locked(root, &v2_store, &flags, max_age)
        })?
    } else {
        with_shared_lock(root.store_lock(), || {
            run_locked(root, &v2_store, &flags, max_age)
        })?
    };

    if json_output {
        emit_json(&summary);
    } else {
        emit_human(&summary, flags.apply);
    }

    Ok(())
}

/// Inner body executed under the store lock. Pulled out so the lock
/// closure has a single sync entry point.
fn run_locked(
    root: &LpmRoot,
    v2_store: &V2Store,
    flags: &PruneFlags<'_>,
    max_age: Option<ChronoDuration>,
) -> Result<PruneSummary, LpmError> {
    let mut summary = compute_prune_plan(root, v2_store, flags, max_age)?;

    if flags.apply {
        // When the registry is missing OR corrupt AND no explicit
        // `--project` was given, `compute_prune_plan` skipped the
        // reachability walk and `link_entries_orphaned` /
        // `object_entries_orphaned` are empty — orphan deletion must
        // be skipped to avoid erroneously wiping the store. The
        // tombstone sweep below still runs because it's independent
        // of project reachability.
        if !summary.registry_missing && !summary.registry_corrupt {
            for orphan in &summary.link_entries_orphaned {
                std::fs::remove_dir_all(orphan).map_err(|e| {
                    LpmError::Store(format!(
                        "cache prune: failed to remove {}: {e}",
                        orphan.display()
                    ))
                })?;
            }
            for orphan in &summary.object_entries_orphaned {
                std::fs::remove_dir_all(orphan).map_err(|e| {
                    LpmError::Store(format!(
                        "cache prune: failed to remove {}: {e}",
                        orphan.display()
                    ))
                })?;
            }
        }

        // Sweep deferred global-uninstall tombstones — best-effort,
        // never fails the caller. Runs unconditionally under
        // `--apply`, including the registry-missing degraded path so
        // `lpm uninstall -g`'s deferred-cleanup retry remains
        // reachable when `~/.lpm/known-projects.json` hasn't been
        // populated yet (registry writes are best-effort during
        // install per `crates/lpm-common/src/known_projects.rs:102`).
        let sweep = match lpm_global::sweep_tombstones(root) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("cache prune: global tombstone sweep failed: {e}");
                lpm_global::SweepReport::default()
            }
        };
        summary.tombstones_swept = sweep.swept.len();
        summary.tombstones_retained = sweep.retained;
        summary.tombstone_bytes_freed = sweep.freed_bytes;
        summary.applied = true;
    }

    Ok(summary)
}

/// Compute (but don't apply) the prune plan. Pulled out so unit tests
/// exercise the algorithm against synthetic stores without touching
/// the filesystem outside of a tempdir.
pub fn compute_prune_plan(
    root: &LpmRoot,
    v2_store: &V2Store,
    flags: &PruneFlags<'_>,
    max_age: Option<ChronoDuration>,
) -> Result<PruneSummary, LpmError> {
    // ── Step 1: Collect root projects ────────────────────────────────
    let registry_path = root.known_projects();
    let mut projects: Vec<PathBuf> = Vec::new();
    let mut registry_entries_dropped = 0usize;

    let mut registry_missing = false;
    let mut registry_corrupt = false;
    let mut registry_corrupt_reason = String::new();
    if let Some(explicit) = flags.project {
        // Manual repair mode: ignore the registry.
        let p = std::fs::canonicalize(explicit).map_err(|e| {
            LpmError::Io(std::io::Error::new(
                e.kind(),
                format!("cache prune: --project {explicit} unreadable: {e}"),
            ))
        })?;
        projects.push(p);
    } else {
        // Default mode, registry-backed. Dry-run must not mutate the
        // registry — the shared store lock allows multiple readers
        // (installs, audits, queries) to run concurrently, and a
        // concurrent install's `register()` write could race a
        // dry-run's `drop_missing()` rewrite and lose the freshly
        // registered project. Read-only walk in dry-run; conditional
        // rewrite in `--apply` (under the exclusive store lock, where
        // installs are blocked from holding the shared half).
        //
        // `try_load` distinguishes missing-vs-corrupt. The lossy
        // [`known_projects::load`] used by the install path collapses
        // both to an empty registry — fine for installs (they degrade
        // to "no recorded projects yet"), DANGEROUS for prune
        // (`--apply` would treat the empty root set as authoritative
        // and mark every link entry as orphaned). Both degraded
        // states here skip the orphan walk; the corrupt branch also
        // emits an actionable reason so the user knows to delete the
        // file or pass `--project`.
        match known_projects::try_load(&registry_path) {
            Ok(registry) => {
                let mut missing_count = 0usize;
                for entry in &registry.projects {
                    if entry.path.exists() {
                        projects.push(entry.path.clone());
                    } else {
                        missing_count += 1;
                    }
                }
                if flags.apply && missing_count > 0 {
                    registry_entries_dropped = known_projects::drop_missing(&registry_path)?;
                } else {
                    registry_entries_dropped = missing_count;
                }
            }
            Err(known_projects::LoadError::NotFound) => {
                registry_missing = true;
            }
            Err(other) => {
                registry_corrupt = true;
                registry_corrupt_reason = other.to_string();
            }
        }

        if registry_missing || registry_corrupt {
            // No usable roots — return an empty plan that
            // [`run_locked`] will treat as tombstone-only. The
            // tombstone count is populated so dry-run still surfaces
            // the work `--apply` will do.
            return Ok(PruneSummary {
                applied: false,
                projects_walked: 0,
                registry_entries_dropped: 0,
                link_entries_total: 0,
                link_entries_reachable: 0,
                link_entries_orphaned: Vec::new(),
                object_entries_total: 0,
                object_entries_reachable: 0,
                object_entries_orphaned: Vec::new(),
                bytes_freed_or_eligible: 0,
                tombstones_pending: lpm_global::count_pending_tombstones(root),
                tombstones_swept: 0,
                tombstones_retained: Vec::new(),
                tombstone_bytes_freed: 0,
                registry_missing,
                registry_corrupt,
                registry_corrupt_reason,
            });
        }
    }

    // ── Step 2: Walk each project's `node_modules/` to collect root
    //         graph-keys (link entries reachable from project roots).
    let links_root_canonical = std::fs::canonicalize(v2_store.paths().links_root())
        .unwrap_or_else(|_| v2_store.paths().links_root());
    let mut root_link_dirs: HashSet<PathBuf> = HashSet::new();
    for project in &projects {
        collect_project_link_roots(project, &links_root_canonical, &mut root_link_dirs);
    }

    // ── Step 3: BFS through link-meta sidecar `deps[].target_graph_key`
    //         to mark every reachable link entry.
    //
    // Canonicalize every link_dir up front so the BFS frontier (which
    // arrives canonicalized from `add_if_link_descendant`) compares
    // cleanly against entries here. macOS's `/private/var/folders/...`
    // canonical form vs. `/var/folders/...` symlink-shape would
    // otherwise prevent the match and leave every entry "unreachable"
    // even from a project that explicitly symlinks into it.
    let raw_entries: Vec<(PathBuf, lpm_store::v2::LinkMeta)> =
        v2_store.iter_link_entries()?.collect();
    let all_link_entries: Vec<(PathBuf, lpm_store::v2::LinkMeta)> = raw_entries
        .into_iter()
        .map(|(dir, meta)| {
            let canonical = std::fs::canonicalize(&dir).unwrap_or(dir);
            (canonical, meta)
        })
        .collect();

    let mut by_digest: std::collections::HashMap<String, PathBuf> =
        std::collections::HashMap::with_capacity(all_link_entries.len());
    for (dir, meta) in &all_link_entries {
        by_digest.insert(meta.graph_key_digest_hex.clone(), dir.clone());
    }

    let link_entries_total = all_link_entries.len();

    let mut reachable: HashSet<PathBuf> = HashSet::new();
    let mut frontier: Vec<PathBuf> = root_link_dirs.iter().cloned().collect();
    while let Some(dir) = frontier.pop() {
        if !reachable.insert(dir.clone()) {
            continue;
        }
        // Find this entry's sidecar and walk its dep edges.
        if let Some((_, meta)) = all_link_entries.iter().find(|(d, _)| d == &dir) {
            for dep in &meta.deps {
                if let Some(target_dir) = by_digest.get(&dep.target_graph_key) {
                    frontier.push(target_dir.clone());
                }
            }
        }
    }

    // ── Step 4: Apply --max-age filter to mark "young" orphans as live.
    let now = Utc::now();
    let mut link_entries_orphaned = Vec::new();
    for (dir, meta) in &all_link_entries {
        if reachable.contains(dir) {
            continue;
        }
        if let Some(max_age) = max_age {
            // followup #3 — the JSON `last_referenced_at`
            // field is set at first population and never rewritten
            // post-followup; cache-hit installs refresh the sidecar
            // file's mtime instead. `effective_last_referenced_at`
            // returns max(json_field, file_mtime) so this filter
            // sees fresh installs even though the JSON itself is
            // immutable. Schema-compatible with pre-followup
            // sidecars (where touch rewrote the field — the json
            // field is still ≤ mtime in the worst case).
            let sidecar_path = dir.join(lpm_store::v2::LINK_META_FILENAME);
            let last_seen = meta.effective_last_referenced_at(&sidecar_path);
            if (now - last_seen) < max_age {
                // Young entry — preserve under the "registry might
                // be stale; entry might be in-use by an unrecorded
                // project" assumption.
                continue;
            }
        }
        link_entries_orphaned.push(dir.clone());
    }

    // ── Step 5: Object orphan detection (preplan). An object is
    //         reachable iff a SURVIVING (non-orphan) link entry's
    //         sidecar lists it as `object_path`. Iterating ALL link
    //         entries — including orphans — would mark every object
    //         reachable as a side effect of the orphan link entries
    //         that haven't been deleted yet, defeating prune
    //         entirely.
    let orphan_link_set: HashSet<&PathBuf> = link_entries_orphaned.iter().collect();
    let mut object_referenced_segments: HashSet<String> = HashSet::new();
    for (dir, meta) in &all_link_entries {
        if orphan_link_set.contains(dir) {
            continue;
        }
        // `LinkMeta.object_path` is `objects/<segment>` relative to the
        // store root. Strip the prefix to align with iter_object_dirs's
        // segment.
        let segment = meta
            .object_path
            .strip_prefix("objects/")
            .unwrap_or(&meta.object_path)
            .trim_end_matches('/')
            .to_string();
        object_referenced_segments.insert(segment);
    }

    let mut object_entries_total = 0usize;
    let mut object_entries_orphaned = Vec::new();
    for (object_dir, segment) in v2_store.iter_object_dirs()? {
        object_entries_total += 1;
        if !object_referenced_segments.contains(&segment) {
            object_entries_orphaned.push(object_dir);
        }
    }

    let mut bytes_freed_or_eligible = 0u64;
    for dir in &link_entries_orphaned {
        bytes_freed_or_eligible =
            bytes_freed_or_eligible.saturating_add(dir_size(dir).unwrap_or(0));
    }
    for dir in &object_entries_orphaned {
        bytes_freed_or_eligible =
            bytes_freed_or_eligible.saturating_add(dir_size(dir).unwrap_or(0));
    }

    Ok(PruneSummary {
        applied: false,
        projects_walked: projects.len(),
        registry_entries_dropped,
        link_entries_total,
        link_entries_reachable: reachable.len(),
        link_entries_orphaned,
        object_entries_total,
        object_entries_reachable: object_referenced_segments.len(),
        object_entries_orphaned,
        bytes_freed_or_eligible,
        tombstones_pending: lpm_global::count_pending_tombstones(root),
        tombstones_swept: 0,
        tombstones_retained: Vec::new(),
        tombstone_bytes_freed: 0,
        registry_missing,
        registry_corrupt,
        registry_corrupt_reason,
    })
}

/// Walk `<project>/node_modules/<entry>` symlinks and add any whose
/// canonical path lies inside `links_root_canonical` to `out`. Skips
/// dotfiles, `.bin/`, and broken symlinks.
fn collect_project_link_roots(
    project: &Path,
    links_root_canonical: &Path,
    out: &mut HashSet<PathBuf>,
) {
    let nm = project.join("node_modules");
    let Ok(entries) = std::fs::read_dir(&nm) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if name.starts_with('@') && path.is_dir() {
            // Scoped — recurse one level into `node_modules/@scope/`.
            if let Ok(scoped) = std::fs::read_dir(&path) {
                for s in scoped.flatten() {
                    add_if_link_descendant(&s.path(), links_root_canonical, out);
                }
            }
            continue;
        }
        add_if_link_descendant(&path, links_root_canonical, out);
    }
}

fn add_if_link_descendant(
    candidate: &Path,
    links_root_canonical: &Path,
    out: &mut HashSet<PathBuf>,
) {
    let Ok(canonical) = std::fs::canonicalize(candidate) else {
        return;
    };
    if !canonical.starts_with(links_root_canonical) {
        return;
    }
    // The canonical path is `<store>/links/<key>/node_modules/<pkg>/`.
    // The `links/<key>` directory itself is the link entry root —
    // strip the `node_modules/<pkg>/` tail to get there.
    let mut walk = canonical.clone();
    while walk.parent().is_some_and(|p| p != links_root_canonical) {
        walk.pop();
    }
    if walk.parent() == Some(links_root_canonical) {
        out.insert(walk);
    }
}

fn parse_duration(s: &str) -> Result<ChronoDuration, LpmError> {
    let (num_str, unit) = if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 'd')
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 'h')
    } else {
        return Err(LpmError::Registry(format!(
            "cache prune: invalid --max-age {s} (use '7d' or '24h')"
        )));
    };
    let num: i64 = num_str
        .parse()
        .map_err(|_| LpmError::Registry(format!("cache prune: invalid number in --max-age {s}")))?;
    if num <= 0 {
        return Err(LpmError::Registry(format!(
            "cache prune: --max-age must be positive, got {s}"
        )));
    }
    Ok(match unit {
        'd' => ChronoDuration::days(num),
        'h' => ChronoDuration::hours(num),
        _ => unreachable!(),
    })
}

fn dir_size(dir: &Path) -> std::io::Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_file() {
            total = total.saturating_add(meta.len());
        } else if meta.is_dir() {
            total = total.saturating_add(dir_size(&entry.path())?);
        }
    }
    Ok(total)
}

fn emit_human(summary: &PruneSummary, applied: bool) {
    use lpm_common::format_bytes;

    if summary.registry_corrupt {
        // Corruption path: registry file exists but parses as
        // garbage / wrong schema / unreadable. Treat as no roots
        // (same as missing) but flag the corruption so the user can
        // act — silently degrading would hide a real problem with
        // their machine state.
        output::warn(&format!(
            "Project registry at ~/.lpm/known-projects.json is unusable ({reason}). \
             Delete the file (a fresh `lpm install` will recreate it) or pass \
             `--project <path>` to walk a specific project. Orphan detection is \
             skipped to avoid wiping the store; tombstone sweep still runs under --apply.",
            reason = summary.registry_corrupt_reason,
        ));
    } else if summary.registry_missing {
        // Degraded path: no project registry → no roots → orphan
        // detection is unsafe. Tombstone sweep still runs under
        // `--apply`. Surface this prominently so the user knows
        // why the orphan numbers aren't reported.
        output::warn(
            "No project registry at ~/.lpm/known-projects.json — \
             run `lpm install` in a project to populate it, or pass \
             `--project <path>` to walk a specific project. Orphan \
             detection is skipped without roots; tombstone sweep \
             still runs under --apply.",
        );
    } else if applied {
        output::success(&format!(
            "Pruned {} link entr{} + {} object{} ({})",
            summary.link_entries_orphaned.len(),
            if summary.link_entries_orphaned.len() == 1 {
                "y"
            } else {
                "ies"
            },
            summary.object_entries_orphaned.len(),
            if summary.object_entries_orphaned.len() == 1 {
                ""
            } else {
                "s"
            },
            format_bytes(summary.bytes_freed_or_eligible),
        ));
    } else {
        output::info(&format!(
            "{} orphan link entries, {} orphan objects ({} eligible to free; pass --apply to remove)",
            summary.link_entries_orphaned.len(),
            summary.object_entries_orphaned.len(),
            format_bytes(summary.bytes_freed_or_eligible),
        ));
    }
    if applied && summary.tombstones_swept > 0 {
        output::success(&format!(
            "Swept {} global-install tombstone(s) (freed {})",
            summary.tombstones_swept,
            format_bytes(summary.tombstone_bytes_freed),
        ));
    }
    if applied && !summary.tombstones_retained.is_empty() {
        output::warn(&format!(
            "{} tombstone(s) could not be cleaned (files in use?); will retry on next prune",
            summary.tombstones_retained.len(),
        ));
        for failure in &summary.tombstones_retained {
            output::warn(&format!("  {}: {}", failure.relative_path, failure.reason));
        }
    }
    if !applied && summary.tombstones_pending > 0 {
        output::info(&format!(
            "{} pending global-install tombstone(s) — `lpm cache prune --apply` will sweep them",
            summary.tombstones_pending,
        ));
    }
    if summary.registry_entries_dropped > 0 {
        output::info(&format!(
            "Dropped {} stale registry entr{}",
            summary.registry_entries_dropped,
            if summary.registry_entries_dropped == 1 {
                "y"
            } else {
                "ies"
            },
        ));
    }
    if !applied && summary.link_entries_orphaned.len() <= 20 {
        for dir in &summary.link_entries_orphaned {
            println!("  link orphan: {}", dir.display());
        }
        for dir in &summary.object_entries_orphaned {
            println!("  object orphan: {}", dir.display());
        }
    }
}

fn emit_json(summary: &PruneSummary) {
    let json = serde_json::json!({
        "applied": summary.applied,
        "projects_walked": summary.projects_walked,
        "registry_entries_dropped": summary.registry_entries_dropped,
        "link_entries_total": summary.link_entries_total,
        "link_entries_reachable": summary.link_entries_reachable,
        "link_entries_orphaned": summary
            .link_entries_orphaned
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "object_entries_total": summary.object_entries_total,
        "object_entries_reachable": summary.object_entries_reachable,
        "object_entries_orphaned": summary
            .object_entries_orphaned
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "bytes_freed_or_eligible": summary.bytes_freed_or_eligible,
        "registry_missing": summary.registry_missing,
        "registry_corrupt": summary.registry_corrupt,
        "registry_corrupt_reason": summary.registry_corrupt_reason,
        "tombstones_pending": summary.tombstones_pending,
        "tombstones_swept": summary.tombstones_swept,
        "tombstones_retained": summary
            .tombstones_retained
            .iter()
            .map(|f| serde_json::json!({
                "relative_path": f.relative_path,
                "reason": f.reason,
            }))
            .collect::<Vec<_>>(),
        "tombstone_bytes_freed": summary.tombstone_bytes_freed,
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use lpm_common::known_projects::{Entry, Registry};
    use lpm_store::v2::{
        DepLink, GraphKey, GraphKeyInputs, LinkEntryRequest, LinkMetaPlatform, LinkerModeTag,
        PlatformTuple,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    fn synthetic_sri(seed: &[u8]) -> String {
        lpm_store::compute_sri_hash(seed)
    }

    fn write_object(store: &V2Store, sri: &str) {
        let dir = store.paths().object_dir(sri).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            br#"{"name":"x","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(dir.join(".integrity"), sri).unwrap();
    }

    fn sample_meta_platform() -> LinkMetaPlatform {
        LinkMetaPlatform {
            os: "darwin".into(),
            cpu: "arm64".into(),
            libc: None,
        }
    }

    fn key_for(name: &str, version: &str) -> Arc<GraphKey> {
        let inputs = GraphKeyInputs::new(
            name,
            version,
            PlatformTuple::current(),
            LinkerModeTag::Isolated,
        );
        Arc::new(GraphKey::derive(&inputs))
    }

    /// Helper: synthesize a project whose `node_modules/<dep>` symlinks
    /// point at `links/<key>/node_modules/<dep>/` for each given key.
    fn synthesize_project(project: &Path, store: &V2Store, keys: &[(&str, Arc<GraphKey>)]) {
        let nm = project.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        for (name, key) in keys {
            let target = store.paths().link_package_dir(key);
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, nm.join(name)).unwrap();
            #[cfg(windows)]
            {
                let _ = (target, name);
                unimplemented!("test only runs on unix");
            }
        }
    }

    #[test]
    #[cfg(unix)]
    fn compute_prune_plan_marks_unreachable_link_entries() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(&lpm_home).unwrap();
        let root = LpmRoot::from_dir(&lpm_home);
        let store = V2Store::from_lpm_root(&root);

        // Two link entries; only one is reachable from a project.
        let used_sri = synthetic_sri(b"prune/used");
        let orphan_sri = synthetic_sri(b"prune/orphan");
        write_object(&store, &used_sri);
        write_object(&store, &orphan_sri);

        let used_key = key_for("used-pkg", "1.0.0");
        let orphan_key = key_for("orphan-pkg", "1.0.0");
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: used_key.clone(),
                source_sri: used_sri.clone(),
                object_dir: store.paths().object_dir(&used_sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: orphan_key.clone(),
                source_sri: orphan_sri.clone(),
                object_dir: store.paths().object_dir(&orphan_sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        synthesize_project(&project, &store, &[("used-pkg", used_key.clone())]);

        // Register the project.
        known_projects::register(&root.known_projects(), &project).unwrap();

        let summary = compute_prune_plan(&root, &store, &PruneFlags::default(), None).unwrap();

        assert_eq!(summary.link_entries_total, 2);
        assert_eq!(summary.link_entries_reachable, 1);
        assert_eq!(summary.link_entries_orphaned.len(), 1);
        // The orphan must be the unused link entry, not the project's.
        assert!(
            summary.link_entries_orphaned[0]
                .display()
                .to_string()
                .contains("orphan-pkg"),
            "expected orphan-pkg in orphan list, got: {:?}",
            summary.link_entries_orphaned
        );
        // The orphan's object is also orphaned.
        assert_eq!(summary.object_entries_total, 2);
        assert_eq!(summary.object_entries_reachable, 1);
        assert_eq!(summary.object_entries_orphaned.len(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn compute_prune_plan_follows_dep_edges_via_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(&lpm_home).unwrap();
        let root = LpmRoot::from_dir(&lpm_home);
        let store = V2Store::from_lpm_root(&root);

        // Three packages: parent → child → grandchild. Project only
        // symlinks `parent`. BFS through dep edges must mark all three
        // as reachable.
        let parent_sri = synthetic_sri(b"prune-bfs/parent");
        let child_sri = synthetic_sri(b"prune-bfs/child");
        let grand_sri = synthetic_sri(b"prune-bfs/grand");
        write_object(&store, &parent_sri);
        write_object(&store, &child_sri);
        write_object(&store, &grand_sri);

        let parent_key = key_for("parent", "1.0.0");
        let child_key = key_for("child", "1.0.0");
        let grand_key = key_for("grand", "1.0.0");

        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: grand_key.clone(),
                source_sri: grand_sri.clone(),
                object_dir: store.paths().object_dir(&grand_sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: child_key.clone(),
                source_sri: child_sri.clone(),
                object_dir: store.paths().object_dir(&child_sri).unwrap(),
                deps: vec![DepLink {
                    local: "grand".into(),
                    target: grand_key.clone(),
                }],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: parent_key.clone(),
                source_sri: parent_sri.clone(),
                object_dir: store.paths().object_dir(&parent_sri).unwrap(),
                deps: vec![DepLink {
                    local: "child".into(),
                    target: child_key.clone(),
                }],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let project = dir.path().join("project");
        synthesize_project(&project, &store, &[("parent", parent_key.clone())]);
        known_projects::register(&root.known_projects(), &project).unwrap();

        let summary = compute_prune_plan(&root, &store, &PruneFlags::default(), None).unwrap();

        assert_eq!(summary.link_entries_total, 3);
        assert_eq!(
            summary.link_entries_reachable, 3,
            "BFS must mark all three through the dep-edge chain"
        );
        assert!(summary.link_entries_orphaned.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn compute_prune_plan_max_age_preserves_recent_entries() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(&lpm_home).unwrap();
        let root = LpmRoot::from_dir(&lpm_home);
        let store = V2Store::from_lpm_root(&root);

        let sri = synthetic_sri(b"prune-maxage/recent");
        write_object(&store, &sri);
        let key = key_for("recent-orphan", "1.0.0");
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key.clone(),
                source_sri: sri.clone(),
                object_dir: store.paths().object_dir(&sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        // No projects registered → entry is unreachable. But its
        // sidecar's `last_referenced_at` is "now"; with --max-age 30d
        // the entry stays.
        let project = dir.path().join("empty-project");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        known_projects::register(&root.known_projects(), &project).unwrap();

        let summary = compute_prune_plan(
            &root,
            &store,
            &PruneFlags::default(),
            Some(ChronoDuration::days(30)),
        )
        .unwrap();
        assert_eq!(
            summary.link_entries_orphaned.len(),
            0,
            "recent entry must NOT be marked orphan under --max-age 30d"
        );
    }

    #[test]
    #[cfg(unix)]
    fn compute_prune_plan_project_mode_skips_registry() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(&lpm_home).unwrap();
        let root = LpmRoot::from_dir(&lpm_home);
        let store = V2Store::from_lpm_root(&root);

        // Synthesize a stale registry entry pointing at a deleted path
        // — without --project the registry would silently drop it; with
        // --project the registry is bypassed entirely so the drop count
        // stays 0.
        let stale = dir.path().join("stale-project");
        let mut r = Registry::new();
        r.projects.push(Entry {
            path: stale.clone(),
            last_seen: Utc::now(),
        });
        known_projects::write(&root.known_projects(), &r).unwrap();

        let sri = synthetic_sri(b"prune-project/used");
        write_object(&store, &sri);
        let key = key_for("used", "1.0.0");
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: key.clone(),
                source_sri: sri.clone(),
                object_dir: store.paths().object_dir(&sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let project = dir.path().join("real-project");
        synthesize_project(&project, &store, &[("used", key.clone())]);

        let project_str = project.to_str().unwrap().to_string();
        let flags = PruneFlags {
            project: Some(&project_str),
            ..PruneFlags::default()
        };

        let summary = compute_prune_plan(&root, &store, &flags, None).unwrap();
        assert_eq!(summary.projects_walked, 1);
        assert_eq!(
            summary.registry_entries_dropped, 0,
            "--project mode must not touch the registry"
        );
        assert_eq!(summary.link_entries_orphaned.len(), 0);

        // After --project run the stale entry is still there.
        let still_there = known_projects::load(&root.known_projects());
        assert_eq!(still_there.projects.len(), 1);
    }

    /// Avoid an `unused` warning on `HashMap` + `DateTime` re-exports
    /// in test utilities — the helpers above use both transiently.
    fn _force_use(_h: HashMap<(), ()>, _t: DateTime<Utc>) {}
}
