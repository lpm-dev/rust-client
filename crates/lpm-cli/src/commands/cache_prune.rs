//! `lpm cache prune` — implementation.
//!
//! Walks the default v2 and experimental-v3 virtual stores and
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

use crate::install_ui;
use chrono::{Duration as ChronoDuration, Utc};
use lpm_common::{
    LpmError, LpmRoot, known_projects, sanitize_for_terminal, with_exclusive_lock, with_shared_lock,
};
use lpm_store::v2::Store as V2Store;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
    pub cas_trees_total: usize,
    pub cas_tree_files_orphaned: Vec<PathBuf>,
    pub cas_blobs_total: usize,
    pub cas_blob_files_orphaned: Vec<PathBuf>,
    pub cas_source_record_files_orphaned: Vec<PathBuf>,
    pub cas_source_validation_files_orphaned: Vec<PathBuf>,
    pub cas_materialized_total: usize,
    pub cas_materialized_entries_orphaned: Vec<PathBuf>,
    /// `compat/<key>/` cached framework-compatibility islands on disk.
    pub compat_islands_total: usize,
    /// Orphan compat islands — pruneable. An island is orphaned when it is
    /// incomplete (no completion sentinel — crashed mid-build) or, under
    /// `--max-age`, its sentinel mtime (last-used stamp) predates the
    /// cutoff. Without reachability we evict islands by LRU, never by the
    /// project walk, so a complete recently-used island is always kept.
    pub compat_islands_orphaned: Vec<PathBuf>,
    /// Content-addressed lifecycle-build artifacts on disk.
    pub build_artifacts_total: usize,
    /// Incomplete or age-expired lifecycle-build artifacts.
    pub build_artifacts_orphaned: Vec<PathBuf>,
    /// Total bytes that would be / were freed by deleting orphans.
    /// This is the logical sum of eligible file lengths. Hardlinks and
    /// copy-on-write extents can make the physical result smaller.
    pub bytes_freed_or_eligible: u64,
    /// Increase in filesystem free space observed across an applied prune.
    /// `None` for dry-runs, unsupported platforms, or when unrelated writes
    /// make the before/after delta indeterminate.
    pub observed_physical_bytes_freed: Option<u64>,
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
    /// Human-readable failure from counting pending tombstones in
    /// dry-run preview. `Some(_)` indicates the global manifest exists
    /// but `try_count_pending_tombstones` could not read or parse it —
    /// the dry-run preview cannot distinguish "no tombstones" from
    /// "tombstone state unknown" without this field. JSON consumers
    /// rely on it to avoid treating a corrupted manifest as healthy.
    pub tombstone_count_error: Option<String>,
    /// Human-readable failure from `sweep_tombstones` under `--apply`.
    /// `Some(_)` indicates the sweep returned `Err` — e.g. manifest
    /// unreadable, future schema, permission denied. The retained list
    /// stays empty in this case and `tombstones_swept` stays zero, so
    /// without this field the JSON envelope would look identical to a
    /// successful no-op sweep.
    pub tombstone_sweep_error: Option<String>,
}

/// Entry point for the CLI dispatcher. Resolves both virtual stores + flags,
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
    let start = Instant::now();
    let v2_store = V2Store::from_lpm_root_for_version(root, lpm_store::StoreVersion::V2);
    let v3_store = V2Store::from_lpm_root_for_version(root, lpm_store::StoreVersion::V3);
    let max_age = match flags.max_age {
        Some(s) => Some(parse_duration(s)?),
        None => None,
    };

    let summary = if flags.apply {
        with_exclusive_lock(root.store_lock(), || {
            run_all_virtual_stores_locked(root, &v2_store, &v3_store, &flags, max_age)
        })?
    } else {
        with_shared_lock(root.store_lock(), || {
            run_all_virtual_stores_locked(root, &v2_store, &v3_store, &flags, max_age)
        })?
    };

    if json_output {
        emit_json(&summary);
    } else {
        emit_human(&summary, flags.apply, start.elapsed());
    }

    if prune_had_errors(&summary) {
        if json_output {
            return Err(LpmError::ExitCode(1));
        }
        return Err(LpmError::Store(
            "cache prune could not complete every requested cleanup step".into(),
        ));
    }

    Ok(())
}

fn run_all_virtual_stores_locked(
    root: &LpmRoot,
    v2_store: &V2Store,
    v3_store: &V2Store,
    flags: &PruneFlags<'_>,
    max_age: Option<ChronoDuration>,
) -> Result<PruneSummary, LpmError> {
    let free_before = flags
        .apply
        .then(|| filesystem_available_bytes(v3_store.paths().root()))
        .flatten();
    let v2 = run_locked(root, v2_store, flags, max_age, false)?;
    let v3 = run_locked(root, v3_store, flags, max_age, true)?;
    let mut summary = merge_prune_summaries(v2, v3);
    summary.observed_physical_bytes_freed = free_before.and_then(|before| {
        filesystem_available_bytes(v3_store.paths().root())?.checked_sub(before)
    });
    Ok(summary)
}

fn merge_prune_summaries(mut left: PruneSummary, right: PruneSummary) -> PruneSummary {
    left.applied |= right.applied;
    left.projects_walked = left.projects_walked.max(right.projects_walked);
    left.registry_entries_dropped = left
        .registry_entries_dropped
        .max(right.registry_entries_dropped);
    left.link_entries_total = left
        .link_entries_total
        .saturating_add(right.link_entries_total);
    left.link_entries_reachable = left
        .link_entries_reachable
        .saturating_add(right.link_entries_reachable);
    left.link_entries_orphaned
        .extend(right.link_entries_orphaned);
    left.object_entries_total = left
        .object_entries_total
        .saturating_add(right.object_entries_total);
    left.object_entries_reachable = left
        .object_entries_reachable
        .saturating_add(right.object_entries_reachable);
    left.object_entries_orphaned
        .extend(right.object_entries_orphaned);
    left.cas_trees_total = left.cas_trees_total.saturating_add(right.cas_trees_total);
    left.cas_tree_files_orphaned
        .extend(right.cas_tree_files_orphaned);
    left.cas_blobs_total = left.cas_blobs_total.saturating_add(right.cas_blobs_total);
    left.cas_blob_files_orphaned
        .extend(right.cas_blob_files_orphaned);
    left.cas_source_record_files_orphaned
        .extend(right.cas_source_record_files_orphaned);
    left.cas_source_validation_files_orphaned
        .extend(right.cas_source_validation_files_orphaned);
    left.cas_materialized_total = left
        .cas_materialized_total
        .saturating_add(right.cas_materialized_total);
    left.cas_materialized_entries_orphaned
        .extend(right.cas_materialized_entries_orphaned);
    left.compat_islands_total = left
        .compat_islands_total
        .saturating_add(right.compat_islands_total);
    left.compat_islands_orphaned
        .extend(right.compat_islands_orphaned);
    left.build_artifacts_total = left
        .build_artifacts_total
        .saturating_add(right.build_artifacts_total);
    left.build_artifacts_orphaned
        .extend(right.build_artifacts_orphaned);
    left.bytes_freed_or_eligible = left
        .bytes_freed_or_eligible
        .saturating_add(right.bytes_freed_or_eligible);
    left.observed_physical_bytes_freed = left
        .observed_physical_bytes_freed
        .or(right.observed_physical_bytes_freed);
    left.tombstones_pending = left.tombstones_pending.max(right.tombstones_pending);
    left.tombstones_swept = left.tombstones_swept.max(right.tombstones_swept);
    if !right.tombstones_retained.is_empty() {
        left.tombstones_retained = right.tombstones_retained;
    }
    left.tombstone_bytes_freed = left
        .tombstone_bytes_freed
        .saturating_add(right.tombstone_bytes_freed);
    left.registry_missing |= right.registry_missing;
    left.registry_corrupt |= right.registry_corrupt;
    if left.registry_corrupt_reason.is_empty() {
        left.registry_corrupt_reason = right.registry_corrupt_reason;
    }
    left.tombstone_count_error = left.tombstone_count_error.or(right.tombstone_count_error);
    left.tombstone_sweep_error = left.tombstone_sweep_error.or(right.tombstone_sweep_error);
    left
}

fn prune_had_errors(summary: &PruneSummary) -> bool {
    summary.tombstone_count_error.is_some() || summary.tombstone_sweep_error.is_some()
}

/// Inner body executed under the store lock. Pulled out so the lock
/// closure has a single sync entry point.
fn run_locked(
    root: &LpmRoot,
    v2_store: &V2Store,
    flags: &PruneFlags<'_>,
    max_age: Option<ChronoDuration>,
    handle_tombstones: bool,
) -> Result<PruneSummary, LpmError> {
    let mut summary = compute_prune_plan(root, v2_store, flags, max_age)?;

    if !summary.registry_missing && !summary.registry_corrupt {
        let objects_to_remove = summary
            .object_entries_orphaned
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        if let Some(cas_plan) = v2_store.file_cas_prune_plan(&objects_to_remove)? {
            summary.cas_trees_total = cas_plan.trees_total;
            summary.cas_blobs_total = cas_plan.blobs_total;
            summary.cas_tree_files_orphaned = cas_plan.tree_files_orphaned;
            summary.cas_blob_files_orphaned = cas_plan.blob_files_orphaned;
            summary.cas_source_record_files_orphaned = cas_plan.source_record_files_orphaned;
            summary.cas_source_validation_files_orphaned =
                cas_plan.source_validation_files_orphaned;
            summary.cas_materialized_total = cas_plan.materialized_total;
            summary.cas_materialized_entries_orphaned = cas_plan.materialized_entries_orphaned;
            for path in summary
                .cas_tree_files_orphaned
                .iter()
                .chain(&summary.cas_blob_files_orphaned)
                .chain(&summary.cas_source_record_files_orphaned)
                .chain(&summary.cas_source_validation_files_orphaned)
            {
                summary.bytes_freed_or_eligible = summary
                    .bytes_freed_or_eligible
                    .saturating_add(path.metadata().map_or(0, |metadata| metadata.len()));
            }
            for entry in &summary.cas_materialized_entries_orphaned {
                summary.bytes_freed_or_eligible = summary
                    .bytes_freed_or_eligible
                    .saturating_add(dir_size(entry).unwrap_or(0));
            }
        }
    }

    if flags.apply {
        let prune_tombstones = v2_store.paths().root().join(".prune-tombstones");
        sweep_prune_tombstones(&prune_tombstones)?;
        // When the registry is missing OR corrupt AND no explicit
        // `--project` was given, `compute_prune_plan` skipped the
        // reachability walk and `link_entries_orphaned` /
        // `object_entries_orphaned` are empty — orphan deletion must
        // be skipped to avoid erroneously wiping the store. The
        // tombstone sweep below still runs because it's independent
        // of project reachability.
        if !summary.registry_missing && !summary.registry_corrupt {
            for orphan in &summary.link_entries_orphaned {
                remove_via_prune_tombstone(orphan, &prune_tombstones)?;
            }
            for orphan in &summary.object_entries_orphaned {
                remove_via_prune_tombstone(orphan, &prune_tombstones)?;
            }
            for source_record in &summary.cas_source_record_files_orphaned {
                remove_via_prune_tombstone(source_record, &prune_tombstones)?;
            }
            for validation in &summary.cas_source_validation_files_orphaned {
                remove_via_prune_tombstone(validation, &prune_tombstones)?;
            }
            for entry in &summary.cas_materialized_entries_orphaned {
                remove_via_prune_tombstone(entry, &prune_tombstones)?;
            }
            for manifest in &summary.cas_tree_files_orphaned {
                remove_via_prune_tombstone(manifest, &prune_tombstones)?;
            }
            for blob in &summary.cas_blob_files_orphaned {
                remove_via_prune_tombstone(blob, &prune_tombstones)?;
            }
        }

        // Compat-island eviction runs unconditionally under `--apply` —
        // unlike link/object orphan deletion it's LRU + crash-recovery
        // (never reachability), so a missing/corrupt registry can't make it
        // wrongly wipe a live island.
        for island in &summary.compat_islands_orphaned {
            remove_via_prune_tombstone(island, &prune_tombstones)?;
        }
        for artifact in &summary.build_artifacts_orphaned {
            remove_via_prune_tombstone(artifact, &prune_tombstones)?;
        }
        remove_orphaned_build_locks(v2_store)?;
        remove_orphaned_build_entry_locks(v2_store)?;

        // Sweep deferred global-uninstall tombstones. Errors are
        // surfaced via `summary.tombstone_sweep_error` (and a
        // `tracing::warn`) instead of being collapsed into an empty
        // report — that's the L53 contract: the JSON envelope and the
        // human output must let consumers tell "no tombstones" apart
        // from "could not inspect tombstones." Runs unconditionally
        // under `--apply`, including the registry-missing degraded
        // path so `lpm uninstall -g`'s deferred-cleanup retry remains
        // reachable when `~/.lpm/known-projects.json` hasn't been
        // populated yet (registry writes are best-effort during
        // install per `crates/lpm-common/src/known_projects.rs:102`).
        if handle_tombstones {
            match lpm_global::sweep_tombstones(root) {
                Ok(sweep) => {
                    summary.tombstones_swept = sweep.swept.len();
                    summary.tombstones_retained = sweep.retained;
                    summary.tombstone_bytes_freed = sweep.freed_bytes;
                }
                Err(e) => {
                    let msg = e.to_string();
                    tracing::warn!("cache prune: global tombstone sweep failed: {msg}");
                    summary.tombstone_sweep_error = Some(msg);
                }
            }
        }
        summary.applied = true;
    }

    Ok(summary)
}

fn remove_via_prune_tombstone(path: &Path, tombstone_root: &Path) -> Result<(), LpmError> {
    use rand::RngCore;

    ensure_prune_tombstone_root(tombstone_root)?;
    let suffix = rand::thread_rng().next_u64();
    let label = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("entry");
    let tombstone = tombstone_root.join(format!("{label}.{suffix:016x}"));
    match std::fs::rename(path, &tombstone) {
        Ok(()) => remove_prune_tombstone(&tombstone),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LpmError::Store(format!(
            "cache prune: failed to tombstone {}: {error}",
            path.display()
        ))),
    }
}

fn ensure_prune_tombstone_root(path: &Path) -> Result<(), LpmError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    Ok(())
}

fn sweep_prune_tombstones(tombstone_root: &Path) -> Result<(), LpmError> {
    let entries = match std::fs::read_dir(tombstone_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        remove_prune_tombstone(&entry?.path())?;
    }
    Ok(())
}

fn remove_prune_tombstone(path: &Path) -> Result<(), LpmError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() {
        std::fs::remove_dir_all(path)?;
    } else {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn remove_orphaned_build_locks(store: &V2Store) -> Result<(), LpmError> {
    let entries = match std::fs::read_dir(store.paths().build_locks_root()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let Some(key) = advisory_lock_key(&path) else {
            continue;
        };
        if !store.paths().builds_root().join(key).is_dir() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn remove_orphaned_build_entry_locks(store: &V2Store) -> Result<(), LpmError> {
    let mut live_graph_keys = HashSet::new();
    match std::fs::read_dir(store.paths().links_root()) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                    continue;
                }
                if let Ok(metadata) = lpm_store::v2::LinkMeta::read_from(&entry.path()) {
                    live_graph_keys.insert(metadata.graph_key_digest_hex);
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let entries = match std::fs::read_dir(store.paths().build_entry_locks_root()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        let Some(key) = advisory_lock_key(&path) else {
            continue;
        };
        if !live_graph_keys.contains(key) {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn advisory_lock_key(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let key = [".lock.writer-intent", ".lock.writer-queue", ".lock"]
        .into_iter()
        .find_map(|suffix| name.strip_suffix(suffix))?;
    (key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    .then_some(key)
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
            let (tombstones_pending, tombstone_count_error) =
                count_tombstones_with_error_capture(root);
            // Island prune is LRU + crash-recovery only (reachability-
            // independent), so it is safe even with no usable registry.
            let (compat_islands_total, compat_islands_orphaned) =
                compute_compat_island_orphans(v2_store.paths().compat_root(), max_age);
            let (build_artifacts_total, build_artifacts_orphaned) =
                compute_build_artifact_orphans(v2_store.paths().builds_root(), max_age);
            let bytes_freed_or_eligible = compat_islands_orphaned
                .iter()
                .chain(&build_artifacts_orphaned)
                .map(|dir| dir_size(dir).unwrap_or(0))
                .fold(0u64, u64::saturating_add);
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
                cas_trees_total: 0,
                cas_tree_files_orphaned: Vec::new(),
                cas_blobs_total: 0,
                cas_blob_files_orphaned: Vec::new(),
                cas_source_record_files_orphaned: Vec::new(),
                cas_source_validation_files_orphaned: Vec::new(),
                cas_materialized_total: 0,
                cas_materialized_entries_orphaned: Vec::new(),
                compat_islands_total,
                compat_islands_orphaned,
                build_artifacts_total,
                build_artifacts_orphaned,
                bytes_freed_or_eligible,
                observed_physical_bytes_freed: None,
                tombstones_pending,
                tombstones_swept: 0,
                tombstones_retained: Vec::new(),
                tombstone_bytes_freed: 0,
                registry_missing,
                registry_corrupt,
                registry_corrupt_reason,
                tombstone_count_error,
                tombstone_sweep_error: None,
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
    // Each entry carries both its raw store-child path (used for
    // deletion under `--apply`) and its canonical path (used for BFS
    // comparison against `add_if_link_descendant`'s canonical frontier).
    // macOS's `/private/var/folders/...` canonical form vs.
    // `/var/folders/...` symlink-shape requires the canonical compare;
    // keeping the raw path for deletion ensures `remove_dir_all`
    // operates on the actual store child even when canonicalize would
    // resolve elsewhere. The store-side `iter_link_entries` refuses
    // symlinks at `links/<entry>` (see store.rs), so the raw path is
    // always a direct store child; the `starts_with` defence below is
    // belt-and-suspenders for any future regression.
    let raw_entries: Vec<(PathBuf, lpm_store::v2::LinkMeta)> =
        v2_store.iter_link_entries()?.collect();
    let mut all_link_entries: Vec<(PathBuf, PathBuf, lpm_store::v2::LinkMeta)> =
        Vec::with_capacity(raw_entries.len());
    for (raw_dir, meta) in raw_entries {
        let canonical_dir = std::fs::canonicalize(&raw_dir).unwrap_or_else(|_| raw_dir.clone());
        if !canonical_dir.starts_with(&links_root_canonical) {
            tracing::warn!(
                "cache prune: skipping link entry at {} — canonical path {} escapes the canonical links root {} (corrupted store?)",
                raw_dir.display(),
                canonical_dir.display(),
                links_root_canonical.display(),
            );
            continue;
        }
        all_link_entries.push((raw_dir, canonical_dir, meta));
    }

    let mut by_digest: std::collections::HashMap<String, PathBuf> =
        std::collections::HashMap::with_capacity(all_link_entries.len());
    for (_, canonical_dir, meta) in &all_link_entries {
        by_digest.insert(meta.graph_key_digest_hex.clone(), canonical_dir.clone());
    }

    let link_entries_total = all_link_entries.len();

    let mut reachable: HashSet<PathBuf> = HashSet::new();
    let mut frontier: Vec<PathBuf> = root_link_dirs.iter().cloned().collect();
    while let Some(dir) = frontier.pop() {
        if !reachable.insert(dir.clone()) {
            continue;
        }
        if let Some((_, _, meta)) = all_link_entries
            .iter()
            .find(|(_, canonical, _)| canonical == &dir)
        {
            for dep in &meta.deps {
                if let Some(target_dir) = by_digest.get(&dep.target_graph_key) {
                    frontier.push(target_dir.clone());
                }
            }
        }
    }

    // ── Step 4: Apply --max-age filter to mark "young" orphans as live.
    //
    // Orphan list stores the RAW store-child path — the deletion path
    // in `run_locked` calls `remove_dir_all` on it directly, so the
    // canonical-form is intentionally not used for that purpose.
    let now = Utc::now();
    let mut link_entries_orphaned = Vec::new();
    for (raw_dir, canonical_dir, meta) in &all_link_entries {
        if reachable.contains(canonical_dir) {
            continue;
        }
        if let Some(max_age) = max_age {
            let sidecar_path = raw_dir.join(lpm_store::v2::LINK_META_FILENAME);
            let last_seen = meta.effective_last_referenced_at(&sidecar_path);
            if (now - last_seen) < max_age {
                continue;
            }
        }
        link_entries_orphaned.push(raw_dir.clone());
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
    for (raw_dir, _, meta) in &all_link_entries {
        if orphan_link_set.contains(raw_dir) {
            continue;
        }
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

    // ── Step 6: Compat-island LRU prune. The island cache (`compat/<key>/`)
    //         is content-keyed and reachability-agnostic, so it is evicted by
    //         LRU — never by the project walk: incomplete islands (crash
    //         recovery) always, complete islands only when `--max-age` finds
    //         their last-used sentinel stale. Absent on non-macOS (islands
    //         are a macOS clonefile feature) → the dir is missing → no-op.
    let (compat_islands_total, compat_islands_orphaned) =
        compute_compat_island_orphans(v2_store.paths().compat_root(), max_age);
    let (build_artifacts_total, build_artifacts_orphaned) =
        compute_build_artifact_orphans(v2_store.paths().builds_root(), max_age);

    let mut bytes_freed_or_eligible = 0u64;
    for dir in &link_entries_orphaned {
        bytes_freed_or_eligible =
            bytes_freed_or_eligible.saturating_add(dir_size(dir).unwrap_or(0));
    }
    for dir in &object_entries_orphaned {
        bytes_freed_or_eligible =
            bytes_freed_or_eligible.saturating_add(dir_size(dir).unwrap_or(0));
    }
    for dir in &compat_islands_orphaned {
        bytes_freed_or_eligible =
            bytes_freed_or_eligible.saturating_add(dir_size(dir).unwrap_or(0));
    }
    for dir in &build_artifacts_orphaned {
        bytes_freed_or_eligible =
            bytes_freed_or_eligible.saturating_add(dir_size(dir).unwrap_or(0));
    }

    let (tombstones_pending, tombstone_count_error) = count_tombstones_with_error_capture(root);

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
        cas_trees_total: 0,
        cas_tree_files_orphaned: Vec::new(),
        cas_blobs_total: 0,
        cas_blob_files_orphaned: Vec::new(),
        cas_source_record_files_orphaned: Vec::new(),
        cas_source_validation_files_orphaned: Vec::new(),
        cas_materialized_total: 0,
        cas_materialized_entries_orphaned: Vec::new(),
        compat_islands_total,
        compat_islands_orphaned,
        build_artifacts_total,
        build_artifacts_orphaned,
        bytes_freed_or_eligible,
        observed_physical_bytes_freed: None,
        tombstones_pending,
        tombstones_swept: 0,
        tombstones_retained: Vec::new(),
        tombstone_bytes_freed: 0,
        registry_missing,
        registry_corrupt,
        registry_corrupt_reason,
        tombstone_count_error,
        tombstone_sweep_error: None,
    })
}

/// Count pending global-uninstall tombstones, capturing any
/// read/parse failure as a human-readable error string. Splits "no
/// tombstones" (returns `(0, None)`) from "could not inspect"
/// (returns `(0, Some(reason))`) so the cache-prune emitters can
/// surface a corruption warning instead of silently reporting zero.
fn count_tombstones_with_error_capture(root: &LpmRoot) -> (usize, Option<String>) {
    match lpm_global::try_count_pending_tombstones(root) {
        Ok(n) => (n, None),
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(
                "cache prune: tombstone count unavailable (manifest unreadable?): {msg}"
            );
            (0, Some(msg))
        }
    }
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
    let mut walk = canonical;
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
        let meta = std::fs::symlink_metadata(entry.path())?;
        if meta.is_file() {
            total = total.saturating_add(meta.len());
        } else if meta.is_dir() {
            total = total.saturating_add(dir_size(&entry.path())?);
        }
    }
    Ok(total)
}

#[cfg(unix)]
fn filesystem_available_bytes(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let mut probe = path.to_path_buf();
    while !probe.try_exists().ok()? {
        if !probe.pop() {
            return None;
        }
    }
    let path = CString::new(probe.as_os_str().as_bytes()).ok()?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stats` points to writable,
    // properly aligned storage that is read only after a successful call.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `statvfs` returned success and initialized the output structure.
    let stats = unsafe { stats.assume_init() };
    let bytes = u128::from(stats.f_bavail).checked_mul(u128::from(stats.f_frsize))?;
    u64::try_from(bytes).ok()
}

#[cfg(not(unix))]
fn filesystem_available_bytes(_path: &Path) -> Option<u64> {
    None
}

/// LRU + crash-recovery orphan detection for the compat-island cache at
/// `~/.lpm/store/v2/compat/`.
///
/// An island is pruneable when it has no completion sentinel (a crashed
/// mid-build leftover) or — only under `--max-age` — when its sentinel mtime
/// (refreshed on every island reuse) is older than the cutoff. Reachability
/// plays no part: islands are content-keyed and shared across projects, so a
/// project walk can't prove an island unused; LRU is the safe policy. A
/// missing `compat/` dir (non-macOS, or no island ever built) yields
/// `(0, [])`. mtime-read / clock-skew failures conservatively keep a complete
/// island.
fn compute_compat_island_orphans(
    compat_root: &Path,
    max_age: Option<ChronoDuration>,
) -> (usize, Vec<PathBuf>) {
    compute_lru_artifact_orphans(
        compat_root,
        lpm_store::v2::COMPAT_ISLAND_COMPLETE_FILENAME,
        max_age,
    )
}

fn compute_build_artifact_orphans(
    builds_root: &Path,
    max_age: Option<ChronoDuration>,
) -> (usize, Vec<PathBuf>) {
    compute_lru_artifact_orphans(
        builds_root,
        lpm_store::v2::BUILD_ARTIFACT_COMPLETE_FILENAME,
        max_age,
    )
}

fn compute_lru_artifact_orphans(
    root: &Path,
    completion_sentinel: &str,
    max_age: Option<ChronoDuration>,
) -> (usize, Vec<PathBuf>) {
    let read = match std::fs::read_dir(root) {
        Ok(read) => read,
        Err(_) => return (0, Vec::new()),
    };
    let max_age_std = max_age.and_then(|d| d.to_std().ok());
    let mut total = 0usize;
    let mut orphaned = Vec::new();
    for entry in read.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let island = entry.path();
        total += 1;
        let sentinel = island.join(completion_sentinel);
        let Ok(meta) = std::fs::metadata(&sentinel) else {
            orphaned.push(island);
            continue;
        };
        if let Some(max_age_std) = max_age_std
            && meta
                .modified()
                .ok()
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|elapsed| elapsed >= max_age_std)
        {
            orphaned.push(island);
        }
    }
    (total, orphaned)
}

fn emit_human(summary: &PruneSummary, applied: bool, elapsed: Duration) {
    use lpm_common::format_bytes;
    let elapsed = install_ui::green(&install_ui::format_duration(elapsed));

    if summary.registry_corrupt {
        // Corruption path: registry file exists but parses as
        // garbage / wrong schema / unreadable. Treat as no roots
        // (same as missing) but flag the corruption so the user can
        // act — silently degrading would hide a real problem with
        // their machine state. Sanitize the reason because it can
        // include parser-controlled bytes from the corrupt file.
        install_ui::warn_untrusted(&format!(
            "Project registry at ~/.lpm/known-projects.json is unusable ({reason}). \
             Delete the file (a fresh `lpm install` will recreate it) or pass \
             `--project <path>` to walk a specific project. Orphan detection is \
             skipped to avoid wiping the store; tombstone sweep still runs under --apply.",
            reason = sanitize_for_terminal(&summary.registry_corrupt_reason),
        ));
    } else if summary.registry_missing {
        // Degraded path: no project registry → no roots → orphan
        // detection is unsafe. Tombstone sweep still runs under
        // `--apply`. Surface this prominently so the user knows
        // why the orphan numbers aren't reported.
        install_ui::warn(
            "No project registry at ~/.lpm/known-projects.json — \
             run `lpm install` in a project to populate it, or pass \
             `--project <path>` to walk a specific project. Orphan \
             detection is skipped without roots; tombstone sweep \
             still runs under --apply.",
        );
    } else if applied {
        let physical = summary
            .observed_physical_bytes_freed
            .map_or_else(|| "unavailable".to_string(), format_bytes);
        install_ui::done_untrusted(&format!(
            "Done · pruned {} link entr{} + {} object{} + {} CAS materializations + {} CAS trees + {} CAS blobs ({} logical; {} physical free-space increase) in {}",
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
            summary.cas_materialized_entries_orphaned.len(),
            summary.cas_tree_files_orphaned.len(),
            summary.cas_blob_files_orphaned.len(),
            format_bytes(summary.bytes_freed_or_eligible),
            physical,
            elapsed,
        ));
    } else {
        install_ui::phase_untrusted(&format!(
            "{} orphan link entries, {} orphan objects, {} orphan CAS materializations, {} orphan CAS trees, {} orphan CAS blobs ({} eligible to free; pass --apply to remove)",
            summary.link_entries_orphaned.len(),
            summary.object_entries_orphaned.len(),
            summary.cas_materialized_entries_orphaned.len(),
            summary.cas_tree_files_orphaned.len(),
            summary.cas_blob_files_orphaned.len(),
            format_bytes(summary.bytes_freed_or_eligible),
        ));
    }
    if applied && summary.tombstones_swept > 0 {
        install_ui::done_untrusted(&format!(
            "Swept {} global-install tombstone(s) (freed {})",
            summary.tombstones_swept,
            format_bytes(summary.tombstone_bytes_freed),
        ));
    }
    if applied && !summary.tombstones_retained.is_empty() {
        install_ui::warn_untrusted(&format!(
            "{} tombstone(s) could not be cleaned (files in use?); will retry on next prune",
            summary.tombstones_retained.len(),
        ));
        for failure in &summary.tombstones_retained {
            install_ui::warn_untrusted(&format!(
                "  {}: {}",
                sanitize_for_terminal(&failure.relative_path),
                sanitize_for_terminal(&failure.reason),
            ));
        }
    }
    if let Some(reason) = &summary.tombstone_sweep_error {
        install_ui::warn_untrusted(&format!(
            "Could not sweep global-install tombstones ({}). The global manifest may be \
             unreadable or corrupted — the retained list is unknown for this run.",
            sanitize_for_terminal(reason),
        ));
    }
    if let Some(reason) = &summary.tombstone_count_error {
        install_ui::warn_untrusted(&format!(
            "Could not inspect pending global-install tombstones ({}). Dry-run reports 0 \
             pending but the actual count is unknown until the manifest is readable.",
            sanitize_for_terminal(reason),
        ));
    }
    if !applied && summary.tombstones_pending > 0 && summary.tombstone_count_error.is_none() {
        install_ui::phase_untrusted(&format!(
            "{} pending global-install tombstone(s) — `lpm cache prune --apply` will sweep them",
            summary.tombstones_pending,
        ));
    }
    if summary.registry_entries_dropped > 0 {
        install_ui::phase_untrusted(&format!(
            "Dropped {} stale registry entr{}",
            summary.registry_entries_dropped,
            if summary.registry_entries_dropped == 1 {
                "y"
            } else {
                "ies"
            },
        ));
    }
    if !summary.compat_islands_orphaned.is_empty() {
        install_ui::phase_untrusted(&format!(
            "{} stale compat island(s) {} {}",
            summary.compat_islands_orphaned.len(),
            if applied { "evicted" } else { "eligible —" },
            if applied {
                String::new()
            } else {
                "`lpm cache prune --apply`".to_string()
            },
        ));
    }
    if !summary.build_artifacts_orphaned.is_empty() {
        install_ui::phase_untrusted(&format!(
            "{} stale build artifact(s) {} {}",
            summary.build_artifacts_orphaned.len(),
            if applied { "evicted" } else { "eligible —" },
            if applied {
                String::new()
            } else {
                "`lpm cache prune --apply`".to_string()
            },
        ));
    }
    if !applied && summary.link_entries_orphaned.len() <= 20 {
        for dir in &summary.link_entries_orphaned {
            println!(
                "  link orphan: {}",
                sanitize_for_terminal(&dir.display().to_string())
            );
        }
        for dir in &summary.object_entries_orphaned {
            println!(
                "  object orphan: {}",
                sanitize_for_terminal(&dir.display().to_string())
            );
        }
        for dir in &summary.compat_islands_orphaned {
            println!(
                "  compat island orphan: {}",
                sanitize_for_terminal(&dir.display().to_string())
            );
        }
        for dir in &summary.build_artifacts_orphaned {
            println!(
                "  build artifact orphan: {}",
                sanitize_for_terminal(&dir.display().to_string())
            );
        }
    }
    if !applied {
        install_ui::done_untrusted(&format!("Done · checked cache in {elapsed}"));
    }
}

fn emit_json(summary: &PruneSummary) {
    let json = serde_json::json!({
        "success": !prune_had_errors(summary),
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
        "cas_trees_total": summary.cas_trees_total,
        "cas_tree_files_orphaned": summary
            .cas_tree_files_orphaned
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "cas_blobs_total": summary.cas_blobs_total,
        "cas_blob_files_orphaned": summary
            .cas_blob_files_orphaned
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "cas_source_record_files_orphaned": summary
            .cas_source_record_files_orphaned
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "cas_source_validation_files_orphaned": summary
            .cas_source_validation_files_orphaned
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "cas_materialized_total": summary.cas_materialized_total,
        "cas_materialized_entries_orphaned": summary
            .cas_materialized_entries_orphaned
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "compat_islands_total": summary.compat_islands_total,
        "compat_islands_orphaned": summary
            .compat_islands_orphaned
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "build_artifacts_total": summary.build_artifacts_total,
        "build_artifacts_orphaned": summary
            .build_artifacts_orphaned
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        "bytes_freed_or_eligible": summary.bytes_freed_or_eligible,
        "logical_bytes_freed_or_eligible": summary.bytes_freed_or_eligible,
        "observed_physical_bytes_freed": summary.observed_physical_bytes_freed,
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
        "tombstone_count_error": summary.tombstone_count_error,
        "tombstone_sweep_error": summary.tombstone_sweep_error,
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;

    #[cfg(unix)]
    use lpm_common::known_projects::{Entry, Registry};
    #[cfg(unix)]
    use lpm_store::v2::{
        DepLink, GraphKey, GraphKeyInputs, LinkEntryRequest, LinkMetaPlatform, LinkerModeTag,
        PlatformTuple,
    };
    use std::collections::HashMap;
    #[cfg(unix)]
    use std::sync::Arc;

    #[cfg(unix)]
    fn synthetic_sri(seed: &[u8]) -> String {
        lpm_store::compute_sri_hash(seed)
    }

    #[cfg(unix)]
    fn test_tarball() -> Vec<u8> {
        use std::io::Write;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let content = br#"{"name":"x","version":"1.0.0"}"#;
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/package.json", &content[..])
                .unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    #[cfg(unix)]
    fn write_object(store: &V2Store, sri: &str) {
        store.extract_object(sri, &test_tarball()).unwrap();
    }

    #[cfg(unix)]
    fn sample_meta_platform() -> LinkMetaPlatform {
        LinkMetaPlatform {
            os: "darwin".into(),
            cpu: "arm64".into(),
            libc: None,
        }
    }

    #[cfg(unix)]
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
    #[cfg(unix)]
    fn synthesize_project(project: &Path, store: &V2Store, keys: &[(&str, Arc<GraphKey>)]) {
        let nm = project.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        for (name, key) in keys {
            let target = store.paths().link_package_dir(key);
            std::os::unix::fs::symlink(&target, nm.join(name)).unwrap();
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
                graph_key: orphan_key,
                source_sri: orphan_sri.clone(),
                object_dir: store.paths().object_dir(&orphan_sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let project = dir.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        synthesize_project(&project, &store, &[("used-pkg", used_key)]);

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
    fn one_prune_plan_reports_v2_and_v3_orphans_together() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(&lpm_home).unwrap();
        let root = LpmRoot::from_dir(&lpm_home);
        let v2 = V2Store::from_lpm_root_for_version(&root, lpm_store::StoreVersion::V2);
        let v3 = V2Store::from_lpm_root_for_version(&root, lpm_store::StoreVersion::V3);
        let project = dir.path().join("project");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        known_projects::register(&root.known_projects(), &project).unwrap();

        for (store, name, seed) in [
            (&v2, "v2-orphan", b"prune/v2".as_slice()),
            (&v3, "v3-orphan", b"prune/v3".as_slice()),
        ] {
            let sri = synthetic_sri(seed);
            write_object(store, &sri);
            store
                .populate_link_entry(LinkEntryRequest {
                    graph_key: key_for(name, "1.0.0"),
                    source_sri: sri.clone(),
                    object_dir: store.paths().object_dir(&sri).unwrap(),
                    deps: Vec::new(),
                    platform: Arc::new(sample_meta_platform()),
                })
                .unwrap();
        }

        let summary =
            run_all_virtual_stores_locked(&root, &v2, &v3, &PruneFlags::default(), None).unwrap();

        assert_eq!(summary.link_entries_total, 2);
        assert_eq!(summary.link_entries_orphaned.len(), 2);
        assert!(summary.cas_trees_total > 0);
        assert!(summary.cas_blobs_total > 0);
    }

    #[test]
    fn prune_tombstone_sweep_removes_crash_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let tombstones = dir.path().join(".prune-tombstones");
        let leftover = tombstones.join("stale-entry.0000000000000001");
        std::fs::create_dir_all(&leftover).unwrap();
        std::fs::write(leftover.join("partial"), b"partial").unwrap();

        sweep_prune_tombstones(&tombstones).unwrap();

        assert!(tombstones.read_dir().unwrap().next().is_none());
    }

    #[test]
    fn compat_island_prune_evicts_incomplete_and_stale_islands() {
        let tmp = tempfile::tempdir().unwrap();
        let compat_root = tmp.path().join("compat");
        std::fs::create_dir_all(&compat_root).unwrap();
        let sentinel = lpm_store::v2::COMPAT_ISLAND_COMPLETE_FILENAME;

        // Complete + freshly-used island (sentinel just written).
        let fresh = compat_root.join("fresh");
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(fresh.join(sentinel), b"v1").unwrap();

        // Incomplete island — crashed mid-build, no sentinel.
        let incomplete = compat_root.join("incomplete");
        std::fs::create_dir_all(&incomplete).unwrap();

        // Complete but stale: sentinel mtime backdated 10 days.
        let stale = compat_root.join("stale");
        std::fs::create_dir_all(&stale).unwrap();
        let stale_sentinel = stale.join(sentinel);
        std::fs::write(&stale_sentinel, b"v1").unwrap();
        let ten_days_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 86_400);
        std::fs::File::options()
            .write(true)
            .open(&stale_sentinel)
            .unwrap()
            .set_modified(ten_days_ago)
            .unwrap();

        // No --max-age: only the incomplete (crash-recovery) island is pruned.
        let (total, orphans) = compute_compat_island_orphans(&compat_root, None);
        assert_eq!(total, 3);
        assert_eq!(orphans, vec![incomplete.clone()]);

        // --max-age 7d: incomplete + stale pruned; the fresh island is kept.
        let (total, mut orphans) =
            compute_compat_island_orphans(&compat_root, Some(ChronoDuration::days(7)));
        assert_eq!(total, 3);
        orphans.sort();
        let mut expected = vec![incomplete, stale];
        expected.sort();
        assert_eq!(orphans, expected);

        // Missing compat dir → no-op, never errors.
        assert_eq!(
            compute_compat_island_orphans(&tmp.path().join("nope"), None),
            (0, Vec::new())
        );
    }

    #[test]
    fn build_artifact_prune_evicts_incomplete_and_stale_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let builds_root = tmp.path().join("builds");
        std::fs::create_dir_all(&builds_root).unwrap();
        let sentinel = lpm_store::v2::BUILD_ARTIFACT_COMPLETE_FILENAME;

        let fresh = builds_root.join("fresh");
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(fresh.join(sentinel), b"").unwrap();

        let incomplete = builds_root.join("incomplete");
        std::fs::create_dir_all(&incomplete).unwrap();

        let stale = builds_root.join("stale");
        std::fs::create_dir_all(&stale).unwrap();
        let stale_sentinel = stale.join(sentinel);
        std::fs::write(&stale_sentinel, b"").unwrap();
        let ten_days_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 86_400);
        std::fs::File::options()
            .write(true)
            .open(&stale_sentinel)
            .unwrap()
            .set_modified(ten_days_ago)
            .unwrap();

        let (total, orphans) = compute_build_artifact_orphans(&builds_root, None);
        assert_eq!(total, 3);
        assert_eq!(orphans, vec![incomplete.clone()]);

        let (total, mut orphans) =
            compute_build_artifact_orphans(&builds_root, Some(ChronoDuration::days(7)));
        assert_eq!(total, 3);
        orphans.sort();
        let mut expected = vec![incomplete, stale];
        expected.sort();
        assert_eq!(orphans, expected);
    }

    #[test]
    fn build_artifact_crash_recovery_applies_without_project_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let store = V2Store::from_lpm_root(&root);
        let incomplete = store.paths().builds_root().join("incomplete");
        std::fs::create_dir_all(&incomplete).unwrap();
        std::fs::write(incomplete.join("partial"), b"partial").unwrap();

        let summary = run_locked(
            &root,
            &store,
            &PruneFlags {
                apply: true,
                ..PruneFlags::default()
            },
            None,
            true,
        )
        .unwrap();

        assert!(summary.registry_missing);
        assert_eq!(summary.build_artifacts_orphaned, vec![incomplete.clone()]);
        assert!(!incomplete.exists());
    }

    #[test]
    fn build_lock_cleanup_removes_only_locks_without_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let store = V2Store::from_lpm_root(&root);
        let orphan_key = "a".repeat(64);
        let live_key = "b".repeat(64);
        std::fs::create_dir_all(store.paths().build_locks_root()).unwrap();
        std::fs::create_dir_all(store.paths().builds_root().join(&live_key)).unwrap();
        let orphan_lock = store.paths().build_lock_path_for_key(&orphan_key);
        let live_lock = store.paths().build_lock_path_for_key(&live_key);
        std::fs::write(&orphan_lock, b"").unwrap();
        std::fs::write(format!("{}.writer-intent", orphan_lock.display()), b"").unwrap();
        std::fs::write(format!("{}.writer-queue", orphan_lock.display()), b"").unwrap();
        std::fs::write(&live_lock, b"").unwrap();
        std::fs::write(format!("{}.writer-intent", live_lock.display()), b"").unwrap();
        std::fs::write(format!("{}.writer-queue", live_lock.display()), b"").unwrap();

        remove_orphaned_build_locks(&store).unwrap();

        assert!(!orphan_lock.exists());
        assert!(!std::fs::exists(format!("{}.writer-intent", orphan_lock.display())).unwrap());
        assert!(!std::fs::exists(format!("{}.writer-queue", orphan_lock.display())).unwrap());
        assert!(live_lock.exists());
        assert!(std::fs::exists(format!("{}.writer-intent", live_lock.display())).unwrap());
        assert!(std::fs::exists(format!("{}.writer-queue", live_lock.display())).unwrap());
    }

    #[test]
    fn build_entry_lock_cleanup_removes_only_locks_without_link_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let store = V2Store::from_lpm_root(&root);
        let orphan_key = "a".repeat(64);
        let live_key = "b".repeat(64);
        std::fs::create_dir_all(store.paths().build_entry_locks_root()).unwrap();
        let orphan_lock = store.paths().build_entry_lock_path(&orphan_key).unwrap();
        let live_lock = store.paths().build_entry_lock_path(&live_key).unwrap();
        std::fs::write(&orphan_lock, b"").unwrap();
        std::fs::write(format!("{}.writer-intent", orphan_lock.display()), b"").unwrap();
        std::fs::write(format!("{}.writer-queue", orphan_lock.display()), b"").unwrap();
        std::fs::write(&live_lock, b"").unwrap();
        std::fs::write(format!("{}.writer-intent", live_lock.display()), b"").unwrap();
        std::fs::write(format!("{}.writer-queue", live_lock.display()), b"").unwrap();
        let link_dir = store
            .paths()
            .links_root()
            .join("example@1.0.0+bbbbbbbbbbbbbbbb");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::fs::write(
            link_dir.join(lpm_store::v2::LINK_META_FILENAME),
            format!(
                r#"{{"schema":1,"graph_key":"example@1.0.0+bbbbbbbbbbbbbbbb","graph_key_digest_hex":"{live_key}","name":"example","version":"1.0.0","source_sri":"sha512-example","object_path":"objects/sha512-example","deps":[],"platform":{{"os":"darwin","cpu":"arm64","libc":null}},"created_at":"2026-01-01T00:00:00Z","last_referenced_at":"2026-01-01T00:00:00Z"}}"#
            ),
        )
        .unwrap();

        remove_orphaned_build_entry_locks(&store).unwrap();

        assert!(!orphan_lock.exists());
        assert!(!std::fs::exists(format!("{}.writer-intent", orphan_lock.display())).unwrap());
        assert!(!std::fs::exists(format!("{}.writer-queue", orphan_lock.display())).unwrap());
        assert!(live_lock.exists());
        assert!(std::fs::exists(format!("{}.writer-intent", live_lock.display())).unwrap());
        assert!(std::fs::exists(format!("{}.writer-queue", live_lock.display())).unwrap());
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
                    target: grand_key,
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
                    target: child_key,
                }],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let project = dir.path().join("project");
        synthesize_project(&project, &store, &[("parent", parent_key)]);
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
                graph_key: key,
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
            path: stale,
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
        synthesize_project(&project, &store, &[("used", key)]);

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

    /// A poisoned link entry shaped as a symlink resolving outside the
    /// store must not appear in the orphan list — otherwise `--apply`
    /// would call `remove_dir_all` on the symlink target outside the
    /// store. The store-side filter rejects symlinks at `links/<entry>`
    /// before the prune plan ever sees them; this regression pins that
    /// contract from the cache-prune caller's point of view.
    #[test]
    #[cfg(unix)]
    fn compute_prune_plan_drops_symlinked_link_entry_resolving_outside_store() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(&lpm_home).unwrap();
        let root = LpmRoot::from_dir(&lpm_home);
        let store = V2Store::from_lpm_root(&root);

        let used_sri = synthetic_sri(b"prune-symlink/used");
        write_object(&store, &used_sri);
        let used_key = key_for("used-pkg", "1.0.0");
        store
            .populate_link_entry(LinkEntryRequest {
                graph_key: used_key.clone(),
                source_sri: used_sri.clone(),
                object_dir: store.paths().object_dir(&used_sri).unwrap(),
                deps: vec![],
                platform: Arc::new(sample_meta_platform()),
            })
            .unwrap();

        let outside = dir.path().join("attacker-controlled");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join(lpm_store::v2::LINK_META_FILENAME),
            br#"{"schema":1,"name":"poisoned","version":"99.0.0","source_sri":"sha512-x","object_path":"objects/sha512-x","graph_key_digest_hex":"deadbeef","deps":[],"platform":{"os":"darwin","cpu":"arm64"},"last_referenced_at":"2024-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, store.paths().links_root().join("poisoned-entry"))
            .unwrap();

        let project = dir.path().join("project");
        synthesize_project(&project, &store, &[("used-pkg", used_key)]);
        known_projects::register(&root.known_projects(), &project).unwrap();

        let summary = compute_prune_plan(&root, &store, &PruneFlags::default(), None).unwrap();

        assert_eq!(
            summary.link_entries_total, 1,
            "symlinked entry must not be counted as a valid link entry"
        );
        for orphan in &summary.link_entries_orphaned {
            assert!(
                !orphan.starts_with(&outside),
                "orphan list must not contain a path resolving outside the store: {}",
                orphan.display()
            );
            assert!(
                orphan.file_name().is_none_or(|n| n != "poisoned-entry"),
                "orphan list must not contain the symlinked entry name"
            );
        }

        assert!(
            outside.exists(),
            "outside-of-store directory must still exist after the prune walk"
        );
    }

    /// A corrupt global manifest (parseable file → garbage TOML) must
    /// surface as `tombstone_count_error: Some(...)` in the dry-run
    /// summary instead of collapsing to `tombstones_pending: 0` with
    /// no signal. JSON consumers depend on this to tell "no tombstones"
    /// apart from "could not inspect tombstones."
    #[test]
    #[cfg(unix)]
    fn compute_prune_plan_surfaces_tombstone_count_error_when_manifest_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(&lpm_home).unwrap();
        let root = LpmRoot::from_dir(&lpm_home);

        std::fs::create_dir_all(root.global_root()).unwrap();
        std::fs::write(
            root.global_manifest(),
            b"this = is = not = valid = toml\n[[",
        )
        .unwrap();

        let store = V2Store::from_lpm_root(&root);
        let project = dir.path().join("project");
        std::fs::create_dir_all(project.join("node_modules")).unwrap();
        known_projects::register(&root.known_projects(), &project).unwrap();

        let summary = compute_prune_plan(&root, &store, &PruneFlags::default(), None).unwrap();
        assert_eq!(
            summary.tombstones_pending, 0,
            "count collapses to 0 on read failure, but the error field carries the signal"
        );
        let reason = summary
            .tombstone_count_error
            .as_deref()
            .expect("corrupt manifest must surface a count error");
        assert!(
            reason.to_lowercase().contains("manifest") || reason.to_lowercase().contains("toml"),
            "tombstone_count_error must describe the failure, got: {reason}"
        );
    }

    /// `--apply` against a corrupt global manifest must surface
    /// `tombstone_sweep_error: Some(...)` instead of returning a clean
    /// `tombstones_swept: 0, tombstones_retained: []` shape that would
    /// look identical to a successful no-op sweep.
    #[test]
    #[cfg(unix)]
    fn run_locked_surfaces_tombstone_sweep_error_when_manifest_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_home = dir.path().join("lpm-home");
        std::fs::create_dir_all(&lpm_home).unwrap();
        let root = LpmRoot::from_dir(&lpm_home);

        std::fs::create_dir_all(root.global_root()).unwrap();
        std::fs::write(root.global_manifest(), b"@@@ not toml @@@").unwrap();

        let store = V2Store::from_lpm_root(&root);
        let project = dir.path().join("project");
        synthesize_project(&project, &store, &[]);
        known_projects::register(&root.known_projects(), &project).unwrap();

        let flags = PruneFlags {
            apply: true,
            ..PruneFlags::default()
        };
        let summary = run_locked(&root, &store, &flags, None, true).unwrap();

        assert_eq!(
            summary.tombstones_swept, 0,
            "no tombstones were actually swept under a corrupt manifest"
        );
        assert!(
            summary.tombstones_retained.is_empty(),
            "retained list stays empty on hard sweep failure"
        );
        let reason = summary
            .tombstone_sweep_error
            .as_deref()
            .expect("corrupt manifest must surface a sweep error under --apply");
        assert!(
            !reason.is_empty(),
            "tombstone_sweep_error must be a non-empty reason, got: {reason:?}"
        );
    }

    /// The cache-prune human emitter must scrub control bytes from
    /// state-derived fields (tombstone failure reasons / paths,
    /// registry corruption reasons). The sanitizer is exercised via
    /// `sanitize_for_terminal`; this asserts a worked example so a
    /// future refactor of `emit_human` doesn't silently drop the
    /// scrub.
    #[test]
    fn sanitize_for_terminal_strips_osc_and_bel_from_sample_tombstone_reason() {
        let raw = "installs/evil-pkg@1.0.0\x1b]8;;file:///etc/shadow\x07";
        let cleaned = lpm_common::sanitize_for_terminal(raw);
        assert!(
            !cleaned.contains('\x1b'),
            "ESC must be stripped from {raw:?}, got {cleaned:?}"
        );
        assert!(
            !cleaned.contains('\x07'),
            "BEL must be stripped from {raw:?}, got {cleaned:?}"
        );
        assert!(
            cleaned.contains("installs/evil-pkg@1.0.0"),
            "printable prefix must survive the scrub, got {cleaned:?}"
        );
    }

    /// Avoid an `unused` warning on `HashMap` + `DateTime` re-exports
    /// in test utilities — the helpers above use both transiently.
    fn _force_use(_h: HashMap<(), ()>, _t: DateTime<Utc>) {}
}
