use crate::output;
use crate::overrides_state;
use crate::patch_engine;
use crate::patch_state;
use indicatif::{ProgressBar, ProgressStyle}; // kept for concurrent download progress bar
use lpm_common::LpmError;
use lpm_linker::{LinkResult, LinkTarget, MaterializedPackage};
use lpm_registry::{GateDecision, RegistryClient, evaluate_cached_url};
use lpm_resolver::{
    OverrideHit, OverrideSet, ResolvedPackage, check_unmet_peers, resolve_with_prefetch,
};
use lpm_store::PackageStore;
use lpm_workspace::PatchedDependencyEntry;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::Semaphore;

/// Phase 39 P2: per-(name, version) fetch serialization.
///
/// Before Phase 39, the main task `drain`ed all speculative tarball
/// downloads before the real fetch loop could start (see the
/// `speculation_join.drain` call at the old Phase 38 P3 overlap point).
/// That drain-wait guaranteed `store.has_package` visibility but
/// serialized the tail of speculation behind resolver completion.
///
/// Phase 39 P2 removes the drain and lets the real fetch loop run
/// concurrently with straggling speculations. Without coordination,
/// the real loop would see `has_package == false` for a mid-fetch
/// package and dispatch a wasted duplicate download. This coordinator
/// gives each `(name, version)` its own lazy `AsyncMutex`; every fetch
/// (speculative or real) acquires that lock for the full download →
/// extract → scan → atomic-rename sequence. Sibling tasks wait on the
/// lock, then re-check the store and short-circuit on the hit.
///
/// Leaks: the outer map grows by one entry per unique package fetched
/// in a given install run. ≤ tree_size entries; reclaimed when the
/// coordinator is dropped at end of `run_with_options`.
/// Per-key fetch lock — one `AsyncMutex` per `(name, version)` in-flight.
type FetchLock = Arc<AsyncMutex<()>>;

#[derive(Default)]
struct FetchCoordinator {
    locks: AsyncMutex<HashMap<(String, String), FetchLock>>,
}

impl FetchCoordinator {
    async fn lock_for(&self, name: &str, version: &str) -> FetchLock {
        let mut map = self.locks.lock().await;
        map.entry((name.to_string(), version.to_string()))
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }
}

/// Default concurrent-tarball-download pool size. Overridable per-invocation
/// via `LPM_CONCURRENT_DOWNLOADS=N` for future network-condition A/B.
///
/// Default bumped 16 → 24 on 2026-04-16 after the Phase 38 P3 concurrency
/// A/B matrix (P2/P3 × 16/24/32 permits, 11-run medians each). Key finding:
/// root-only speculation + 16 permits forced transitive downloads to
/// queue behind the speculation drain. 24 permits keeps the tail
/// parallel without HTTP/1.1 connection thrash. 32 went backwards
/// (CDN-side contention or local socket overhead). See phase-38 plan
/// doc for the full matrix.
const DEFAULT_MAX_CONCURRENT_DOWNLOADS: usize = 24;

fn max_concurrent_downloads() -> usize {
    std::env::var("LPM_CONCURRENT_DOWNLOADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0 && n <= 256)
        .unwrap_or(DEFAULT_MAX_CONCURRENT_DOWNLOADS)
}

/// Per-package fetch-stage timings collected inside one download task.
///
/// Populated by the parallel download loop and folded into a
/// [`FetchBreakdown`] aggregate so `lpm install --json` can surface the
/// real sub-stage costs instead of the single lumpy `fetch_ms` number.
/// All values are whole milliseconds.
#[derive(Debug, Clone, Copy, Default)]
struct TaskTimings {
    /// Time from tokio spawn to successful semaphore acquire. High values
    /// indicate download concurrency (the 16-wide permit pool) is the
    /// bottleneck — tasks are queued waiting for a slot rather than
    /// running I/O.
    queue_wait_ms: u128,
    /// Phase 43 — time spent resolving the tarball URL (registry
    /// metadata round-trip when the lockfile didn't have a usable
    /// cached URL; near-zero otherwise). Measured around the
    /// `resolve_tarball_url` call in BOTH legacy and streaming
    /// fetch paths so the direct Phase 43 win is visible on either
    /// path. Carved out of `download_ms` (legacy) and previously
    /// untimed in streaming.
    url_lookup_ms: u128,
    /// Time in `client.download_tarball_to_file` — the HTTP GET +
    /// on-disk temp spool + SHA-512 streaming hash. **Phase 43
    /// note:** URL resolution is now carved out into
    /// `url_lookup_ms` on both paths; `download_ms` covers GET +
    /// temp-file write only (legacy path; streaming collapses
    /// into `extract_ms`).
    download_ms: u128,
    /// Time spent verifying the computed SRI against the expected hash.
    /// Near-zero in the common `sha512` matched case (string compare);
    /// non-trivial only when `integrity.algo` differs from sha512, in
    /// which case the tarball is re-read in 64 KB chunks.
    integrity_ms: u128,
    /// Time in `extract_tarball_from_file` (gzip decompress + tar walk
    /// + write-to-staging). Mirrors [`lpm_store::StageTimings::extract_ms`].
    extract_ms: u128,
    /// Time in the behavioral security scan + `.lpm-security.json` cache
    /// write. The second-filesystem-pass cost that Phase 38 P2 targets.
    /// Mirrors [`lpm_store::StageTimings::security_ms`].
    security_ms: u128,
    /// Time in `.integrity` write + atomic rename into the store path.
    /// Mirrors [`lpm_store::StageTimings::finalize_ms`].
    finalize_ms: u128,
}

/// Aggregate fetch-stage breakdown across the entire parallel download pool.
///
/// Sum fields give total wall-clock spent in each stage across all tasks
/// (useful for CPU/IO attribution). Max fields give the single slowest
/// package's cost (useful for tail-latency analysis). `task_count` is the
/// number of non-cached packages actually downloaded.
///
/// Emitted under `timing.fetch_breakdown` in `lpm install --json`. Both
/// sum- and max- variants are reported so future optimizations can be
/// measured against the stage profile most relevant to the change:
/// stream-to-staging (P1) moves mass out of `extract_sum_ms`; the
/// fused-scan follow-up (P2) should zero out `security_sum_ms`.
#[derive(Debug, Clone, Copy, Default)]
struct FetchBreakdown {
    /// Number of tasks whose timings were folded in (== `downloaded`).
    task_count: u64,
    queue_wait_sum_ms: u128,
    queue_wait_max_ms: u128,
    /// Phase 43 — sum/max of per-task URL-lookup time. Primary
    /// Phase 43 projection target: drops from ~15–25 s to near-0
    /// on fresh-CI installs once stored URLs are reused. Visible
    /// on both legacy and streaming paths by construction.
    url_lookup_sum_ms: u128,
    url_lookup_max_ms: u128,
    download_sum_ms: u128,
    download_max_ms: u128,
    integrity_sum_ms: u128,
    integrity_max_ms: u128,
    extract_sum_ms: u128,
    extract_max_ms: u128,
    security_sum_ms: u128,
    security_max_ms: u128,
    finalize_sum_ms: u128,
    finalize_max_ms: u128,
}

/// Phase 38 P3 speculative-fetch counters.
///
/// Populated by the default install path (Phase 39 P0 flipped speculation
/// on by default). Zero across the board when `LPM_SPEC_FETCH=0` disables
/// the dispatcher, or when every root is already in the store before the
/// metadata RPC starts. Surfaced in `timing.fetch_breakdown.speculative`
/// so benchmarks can attribute the wall-clock delta to actual speculation
/// outcomes.
#[derive(Debug, Clone, Copy, Default)]
struct SpeculativeStats {
    /// Wall-clock of the metadata-stream + dispatcher phase, i.e. the
    /// duration that speculative downloads had to run in parallel with
    /// the remaining NDJSON stream + PubGrub. Roughly equal to the
    /// legacy `batch_metadata_deep` RPC time, but the real work (tarball
    /// downloads) happens inside this window instead of after it.
    streaming_batch_ms: u128,
    /// Total packages the dispatcher started a tarball download for.
    /// Pre-Phase-39-P3 this capped at root count; now includes
    /// transitives reachable via `dispatched_root → dep_range → matching
    /// version` expansion. Excludes store hits, unparseable ranges, and
    /// packages with no range-satisfying version in the arrived manifest.
    dispatched: u64,
    /// Number of dispatched downloads that completed successfully (or
    /// no-op'd because another concurrent task raced us to the store).
    /// Below `dispatched` when a tarball network error or integrity
    /// mismatch caused the spec download to drop.
    completed: u64,
    /// Cumulative wall-clock across all dispatched speculative tasks.
    /// Divide by `completed` for average per-task cost.
    task_ms_sum: u128,
    /// **Phase 39 P3.** Subset of `dispatched` that came from transitive
    /// expansion (i.e. a dep of an already-speculated package). Equal to
    /// `dispatched - roots_dispatched`; reported separately so benchmarks
    /// can confirm transitive reach on larger fixtures.
    transitive_dispatched: u64,
    /// **Phase 39 P3.** Maximum depth reached during transitive expansion
    /// on this install. `1` for root-only installs; climbs with deeper
    /// trees. Capped at [`SPECULATION_MAX_DEPTH`].
    max_depth_reached: u64,
    /// **Phase 39 P3.** Packages whose manifest arrived but whose range
    /// had no matching version — tracked separately from dispatched
    /// misses because a naive user might read the gap between
    /// `dispatched` and `resolve-output` as wastage.
    no_version_match: u64,
    /// **Phase 39 P3.** Packages whose manifest never arrived during
    /// speculation (parked but the parent's deep-walk didn't cover
    /// them). Usually indicates the worker's deep-walk hit its own cap.
    unresolved_parked: u64,
}

impl SpeculativeStats {
    fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "streaming_batch_ms": self.streaming_batch_ms,
            "dispatched": self.dispatched,
            "completed": self.completed,
            "task_ms_sum": self.task_ms_sum,
            "transitive_dispatched": self.transitive_dispatched,
            "max_depth_reached": self.max_depth_reached,
            "no_version_match": self.no_version_match,
            "unresolved_parked": self.unresolved_parked,
        })
    }
}

/// **Phase 39 P3.** Cap on transitive-speculation depth. Prevents
/// unbounded fan-out on pathological trees (e.g. circular deps, or
/// very deep single-chains). Matches the worker's own deep-walk cap so
/// speculation doesn't ask for manifests the worker won't send.
const SPECULATION_MAX_DEPTH: u32 = 5;

impl FetchBreakdown {
    /// Fold one task's timings into the running aggregate.
    fn record(&mut self, t: TaskTimings) {
        self.task_count += 1;
        self.queue_wait_sum_ms += t.queue_wait_ms;
        self.queue_wait_max_ms = self.queue_wait_max_ms.max(t.queue_wait_ms);
        self.url_lookup_sum_ms += t.url_lookup_ms;
        self.url_lookup_max_ms = self.url_lookup_max_ms.max(t.url_lookup_ms);
        self.download_sum_ms += t.download_ms;
        self.download_max_ms = self.download_max_ms.max(t.download_ms);
        self.integrity_sum_ms += t.integrity_ms;
        self.integrity_max_ms = self.integrity_max_ms.max(t.integrity_ms);
        self.extract_sum_ms += t.extract_ms;
        self.extract_max_ms = self.extract_max_ms.max(t.extract_ms);
        self.security_sum_ms += t.security_ms;
        self.security_max_ms = self.security_max_ms.max(t.security_ms);
        self.finalize_sum_ms += t.finalize_ms;
        self.finalize_max_ms = self.finalize_max_ms.max(t.finalize_ms);
    }

    /// Serialize as a JSON object for `lpm install --json` output.
    fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "task_count": self.task_count,
            "queue_wait":  { "sum_ms": self.queue_wait_sum_ms,  "max_ms": self.queue_wait_max_ms  },
            "url_lookup":  { "sum_ms": self.url_lookup_sum_ms,  "max_ms": self.url_lookup_max_ms  },
            "download":    { "sum_ms": self.download_sum_ms,    "max_ms": self.download_max_ms    },
            "integrity":   { "sum_ms": self.integrity_sum_ms,   "max_ms": self.integrity_max_ms   },
            "extract":     { "sum_ms": self.extract_sum_ms,     "max_ms": self.extract_max_ms     },
            "security":    { "sum_ms": self.security_sum_ms,    "max_ms": self.security_max_ms    },
            "finalize":    { "sum_ms": self.finalize_sum_ms,    "max_ms": self.finalize_max_ms    },
        })
    }
}

/// **Phase 43 gate counters.**
///
/// Shared across every fetch task (must be atomic because 24
/// concurrent permit-holders may increment these). Surfaces on
/// `timing.fetch_breakdown` at install-end so an A/B bench can tell
/// whether stored URLs are actually being reused or the gate is
/// incorrectly rejecting them.
///
/// `shape_mismatch > 0` is a BUG signal — the writer should never
/// emit a gate-rejectable URL. `origin_mismatch > 0` is expected
/// after `LPM_REGISTRY_URL` switches (stored origins rebased out).
#[derive(Default, Debug)]
struct GateStats {
    /// Origin-mismatch rejections (cached URL doesn't match current
    /// `{base_url, npm_registry_url}`). Expected non-zero after a
    /// registry switch; drops back to 0 once the writeback trigger
    /// (P43-2 Change 3, landing in a follow-up commit) persists the
    /// rebased URLs.
    origin_mismatch: std::sync::atomic::AtomicU64,
    /// Shape-mismatch rejections (URL path doesn't contain `/-/`
    /// or doesn't end in `.tgz`). Should always be 0 — a writer
    /// regression or a tampered lockfile otherwise.
    shape_mismatch: std::sync::atomic::AtomicU64,
    /// Scheme-mismatch rejections (neither HTTPS nor
    /// `http://localhost`). Same invariant as `shape_mismatch`:
    /// the writer never emits a scheme-unsafe URL, so a non-zero
    /// counter is a corrupt-lockfile signal.
    scheme_mismatch: std::sync::atomic::AtomicU64,
    /// Stored URL 404'd and the same-run retry (refresh metadata
    /// → fetch fresh URL) succeeded. Expected near-zero in steady
    /// state once the writeback trigger lands; persistent non-zero
    /// = stored URLs keep going stale faster than writeback can
    /// refresh them.
    stale_recovery: std::sync::atomic::AtomicU64,
    /// Stored URL 404'd AND the same-run retry also failed (or
    /// the fresh URL matched the stale one, indicating metadata
    /// itself is stuck). Package really isn't reachable — lockfile
    /// gets deleted, user re-resolves.
    stale_hard_fail: std::sync::atomic::AtomicU64,
}

impl GateStats {
    fn to_json(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering;
        serde_json::json!({
            "origin_mismatch_count":  self.origin_mismatch.load(Ordering::Relaxed),
            "shape_mismatch_count":   self.shape_mismatch.load(Ordering::Relaxed),
            "scheme_mismatch_count":  self.scheme_mismatch.load(Ordering::Relaxed),
            "stale_recovery_count":   self.stale_recovery.load(Ordering::Relaxed),
            "stale_hard_fail_count":  self.stale_hard_fail.load(Ordering::Relaxed),
        })
    }
}

/// A workspace member dependency that lives at a source directory inside the
/// current workspace and must be linked locally instead of fetched from the
/// registry. Produced by [`extract_workspace_protocol_deps`] and consumed by
/// [`link_workspace_members`].
///
/// **Phase 32 Phase 2 audit fix #3** (workspace:^ resolver bug):
/// Pre-fix, [`lpm_workspace::resolve_workspace_protocol`] rewrote
/// `"@scope/member": "workspace:^"` into `"@scope/member": "^1.5.0"` and left
/// the entry in `deps`, which then went to the registry resolver and 404'd
/// against npm/upstream because unpublished workspace members can't be fetched
/// remotely. Post-fix, [`extract_workspace_protocol_deps`] strips these
/// entries from `deps` BEFORE the resolver runs and returns them as
/// `WorkspaceMemberLink`s; [`link_workspace_members`] then symlinks them into
/// `node_modules/<name>` directly from the member's source directory after
/// the install pipeline finishes.
#[derive(Debug, Clone)]
struct WorkspaceMemberLink {
    /// Package name as declared in the member's package.json (e.g., `@test/core`).
    name: String,
    /// Concrete version from the member's own package.json `version` field.
    /// Used only for diagnostics — there is no resolver constraint to satisfy.
    version: String,
    /// Absolute path to the member's source directory (the parent of its
    /// `package.json`). The post-link symlink target.
    source_dir: PathBuf,
}

/// Interactive confirmation for multi-member workspace mutations.
///
/// Prints the target set (always, in human mode) and asks "Proceed? [y/N]"
/// only when every precondition for a genuinely-interactive run is met:
/// `yes` flag is false, `json_output` is false, and stdin is a real TTY.
/// Any one of those being true bypasses the prompt without error — the
/// preview still prints so terminal users and log readers see what's about
/// to happen.
///
/// Returns `Err(LpmError::Script)` with a clear "aborted by user" message
/// when the user declines, so callers propagate via `?` and no manifest is
/// touched. I/O errors on stdin fall through to abort for safety.
///
/// **Phase 32 Phase 2 D-impl-5 (2026-04-16):** closes the gap between the
/// original Phase 2 plan (which specified a prompt) and the initial ship
/// (which was preview-only). See the phase 2 status doc's D-impl-5 entry.
pub(crate) fn confirm_multi_member_mutation(
    verb: &str,
    package_count: usize,
    manifests: &[PathBuf],
    yes: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    use std::io::{BufRead, IsTerminal, Write};

    // Preview line: print in human mode regardless of prompt path so users
    // still see the target set even when `--yes` or CI skips the prompt.
    if !json_output {
        output::info(&format!(
            "{} {} package(s) across {} workspace member(s):",
            verb,
            package_count,
            manifests.len(),
        ));
        for path in manifests {
            let label = path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            println!("  {}", label.dimmed());
        }
    }

    // Three bypass paths, in order of decreasing "caller intent": explicit
    // `--yes`, JSON mode, and non-interactive stdin. Any of them skip the
    // prompt entirely. The preview above already ran, so the user still has
    // a paper trail of what we mutated.
    if yes || json_output || !std::io::stdin().is_terminal() {
        return Ok(());
    }

    // Interactive prompt. Default is No — a blank enter aborts, matching
    // every destructive prompt in the codebase.
    let prompt = format!(
        "Proceed with {} {} package(s) across {} members? [y/N] ",
        verb.to_lowercase(),
        package_count,
        manifests.len(),
    );
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => {
            // EOF or I/O error — treat as decline for safety.
            return Err(LpmError::Script(
                "aborted: no input received on stdin (use `--yes` to skip the confirmation)".into(),
            ));
        }
        Ok(_) => {}
    }
    let answer = line.trim().to_lowercase();
    if answer == "y" || answer == "yes" {
        Ok(())
    } else {
        Err(LpmError::Script(format!(
            "aborted by user; no package.json was modified. Pass `--yes` / `-y` to \
             skip this prompt in scripts (got: {:?})",
            line.trim()
        )))
    }
}

/// Strip `workspace:*` / `workspace:^` / `workspace:~` / `workspace:<exact>`
/// dependencies from `deps` and return them as a list of locally-resolvable
/// links. The resolver never sees these entries — they bypass the registry
/// entirely and are linked from disk by [`link_workspace_members`].
///
/// **Phase 32 Phase 2 audit fix #3:** this replaces the previous
/// "[`lpm_workspace::resolve_workspace_protocol`] rewrites in place, then the
/// resolver fetches from the registry" pattern, which 404'd whenever a
/// workspace member was unpublished (the common case in monorepos that
/// internally develop libraries before any release).
///
/// Returns `Err(LpmError::Workspace)` if a `workspace:` reference points at a
/// package name that is not in the workspace's discovered member list. This
/// preserves the validation behavior of `resolve_workspace_protocol` so that
/// typos in cross-member deps still hard-error instead of silently shipping
/// no dependency.
///
/// Members are matched by their declared `package.json` `name` field, not by
/// directory name. The version field is read from the member's own
/// `package.json` (defaulting to `0.0.0` if absent, mirroring how
/// `resolve_workspace_protocol` handled the same case).
fn extract_workspace_protocol_deps(
    deps: &mut HashMap<String, String>,
    workspace: &lpm_workspace::Workspace,
) -> Result<Vec<WorkspaceMemberLink>, LpmError> {
    // First pass: identify the names of workspace: entries. We can't mutate
    // `deps` while iterating it, so we collect the names + their original
    // protocol strings, then validate + remove in a second pass.
    let mut workspace_names: Vec<(String, String)> = deps
        .iter()
        .filter(|(_, range)| range.starts_with("workspace:"))
        .map(|(name, range)| (name.clone(), range.clone()))
        .collect();

    // Deterministic order so the returned list (and any error message) is
    // stable for tests + JSON output. HashMap iteration order is randomized.
    workspace_names.sort_by(|a, b| a.0.cmp(&b.0));

    if workspace_names.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(workspace_names.len());
    for (name, range) in &workspace_names {
        let member = workspace
            .members
            .iter()
            .find(|m| m.package.name.as_deref() == Some(name.as_str()))
            .ok_or_else(|| {
                let mut available: Vec<&str> = workspace
                    .members
                    .iter()
                    .filter_map(|m| m.package.name.as_deref())
                    .collect();
                available.sort();
                let available_str = if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                };
                LpmError::Workspace(format!(
                    "{range} references package '{name}' which is not a workspace member. \
                     Available members: {available_str}"
                ))
            })?;

        let version = member
            .package
            .version
            .as_deref()
            .unwrap_or("0.0.0")
            .to_string();

        extracted.push(WorkspaceMemberLink {
            name: name.clone(),
            version,
            source_dir: member.path.clone(),
        });
    }

    // Validation passed for every entry — now remove them from `deps`.
    for (name, _) in &workspace_names {
        deps.remove(name);
    }

    Ok(extracted)
}

/// Symlink workspace member dependencies into `<project_dir>/node_modules/<name>`.
///
/// Called AFTER `link_packages` (or `link_packages_hoisted`) so that the
/// linker's stale-symlink cleanup pass — which removes any
/// `node_modules/<name>` entry not in `direct_names` — has already run. Our
/// workspace symlinks are not in `direct_names` because workspace members are
/// stripped from `deps` before resolution by [`extract_workspace_protocol_deps`],
/// so they would be wiped on every install if we created them BEFORE the
/// linker. The post-link order also means the helper has to be idempotent
/// across re-runs (it cleans any pre-existing entry at the link path).
///
/// **Phase 32 Phase 6 audit fix (2026-04-12).** Convert one
/// [`patch_engine::AppliedPatch`] into the persisted state-file shape,
/// rewriting absolute paths to project-dir-relative for portability.
/// Pulls `original_integrity` straight from the engine result so the
/// state file (and `lpm graph --why`) carries the actual hash, not a
/// placeholder.
fn applied_patch_to_state_hit(
    a: &patch_engine::AppliedPatch,
    project_dir: &Path,
) -> patch_state::AppliedPatchHit {
    patch_state::AppliedPatchHit {
        raw_key: format!("{}@{}", a.name, a.version),
        name: a.name.clone(),
        version: a.version.clone(),
        patch_path: a
            .patch_path
            .strip_prefix(project_dir)
            .unwrap_or(&a.patch_path)
            .to_string_lossy()
            .to_string(),
        original_integrity: Some(a.original_integrity.clone()),
        locations: a
            .locations_patched
            .iter()
            .map(|p| {
                p.strip_prefix(project_dir)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .to_string()
            })
            .collect(),
        files_modified: a.files_modified,
        files_added: a.files_added,
        files_deleted: a.files_deleted,
    }
}

/// **Phase 32 Phase 6 audit fix (2026-04-12).** Persist
/// `.lpm/patch-state.json` with the right `applied` trace for the
/// install run. Three cases:
///
/// 1. **Work happened this run** (any apply result has non-zero file
///    counts) → capture a fresh trace from the run results.
/// 2. **No work happened this run** (idempotent rerun: every file
///    already had the expected post-patch bytes) AND a prior state
///    file exists → preserve the prior state's `applied` list so
///    `lpm graph --why` doesn't go blind. Mirror of Phase 5
///    `OverridesState::capture_preserving_applied`.
/// 3. **No work happened this run AND no prior state** (rare edge:
///    user pre-staged patched bytes manually) → record what we know
///    (the run results, even if all-zero — the next non-idempotent
///    run will fix this).
///
/// Pre-fix: case (2) overwrote the state file with all-zero results,
/// which made the file count visible in `lpm graph --why` decay to
/// zero on every idempotent rerun.
fn persist_patch_state(
    project_dir: &Path,
    current_patches: &HashMap<String, PatchedDependencyEntry>,
    prior_patch_state: &Option<patch_state::PatchState>,
    applied_patches: &[patch_engine::AppliedPatch],
) {
    if !current_patches.is_empty() {
        let any_work_done = applied_patches.iter().any(|a| a.touched_anything());
        let applied_hits: Vec<patch_state::AppliedPatchHit> =
            if any_work_done || prior_patch_state.is_none() {
                applied_patches
                    .iter()
                    .map(|a| applied_patch_to_state_hit(a, project_dir))
                    .collect()
            } else {
                // No work done; preserve the previous trace (case 2).
                prior_patch_state
                    .as_ref()
                    .map(|s| s.applied.clone())
                    .unwrap_or_default()
            };
        let state = patch_state::PatchState::capture(current_patches, applied_hits);
        if let Err(e) = patch_state::write_state(project_dir, &state) {
            tracing::warn!("failed to write patch-state.json: {e}");
        }
    } else if prior_patch_state.is_some()
        && let Err(e) = patch_state::delete_state(project_dir)
    {
        tracing::warn!("failed to delete stale patch-state.json: {e}");
    }
}

/// **Phase 32 Phase 6 audit fix (2026-04-12).** Build the JSON
/// `applied_patches` array shape from a slice of engine results.
/// Filtering to `touched_anything()` is done by the caller — this
/// helper formats whatever it's given.
fn applied_patches_to_json(
    applied_patches: &[&patch_engine::AppliedPatch],
    project_dir: &Path,
) -> serde_json::Value {
    serde_json::Value::Array(
        applied_patches
            .iter()
            .map(|a| {
                serde_json::json!({
                    "name": a.name,
                    "version": a.version,
                    "patch_path": a
                        .patch_path
                        .strip_prefix(project_dir)
                        .unwrap_or(&a.patch_path)
                        .to_string_lossy(),
                    "original_integrity": a.original_integrity,
                    "locations_patched": a
                        .locations_patched
                        .iter()
                        .map(|p| {
                            p.strip_prefix(project_dir)
                                .unwrap_or(p)
                                .to_string_lossy()
                                .to_string()
                        })
                        .collect::<Vec<_>>(),
                    "files_modified": a.files_modified,
                    "files_added": a.files_added,
                    "files_deleted": a.files_deleted,
                })
            })
            .collect(),
    )
}

/// **Phase 32 Phase 6 — `lpm patch` apply pass.**
///
/// Run unconditionally after the linker (and the workspace-member
/// linker pass). For each entry in `lpm.patchedDependencies`, find every
/// physical destination of the target package via `link_result.materialized`
/// and apply the patch there. Drift, fuzzy hunks, missing files, and
/// internal-file modification attempts are all hard install errors.
///
/// Both online (`run_with_options`) and offline (`run_link_and_finish`)
/// install paths call this exact function — there is no parallel apply
/// logic to keep in sync.
///
/// Returns the per-entry [`patch_engine::AppliedPatch`] vector. The
/// caller threads it into the JSON output and the `.lpm/patch-state.json`
/// persist step.
fn apply_patches_for_install(
    patches: &HashMap<String, PatchedDependencyEntry>,
    link_result: &LinkResult,
    store: &PackageStore,
    project_dir: &Path,
    json_output: bool,
) -> Result<Vec<patch_engine::AppliedPatch>, LpmError> {
    if patches.is_empty() {
        return Ok(Vec::new());
    }

    let mut results: Vec<patch_engine::AppliedPatch> = Vec::with_capacity(patches.len());

    // Iterate in a deterministic order so error messages and the
    // applied list are stable across runs (HashMap iteration is
    // randomized).
    let mut sorted_keys: Vec<&String> = patches.keys().collect();
    sorted_keys.sort();

    for key in sorted_keys {
        let entry = &patches[key];
        let (name, version) = patch_engine::parse_patch_key(key)?;

        // Resolve the patch file path relative to the project dir.
        let patch_file = project_dir.join(&entry.path);
        if !patch_file.exists() {
            return Err(LpmError::Script(format!(
                "patch file {} declared in lpm.patchedDependencies[{key}] does not exist",
                entry.path
            )));
        }

        // Filter the linker's materialized list to physical copies of
        // this package. The linker reports every shape (isolated,
        // hoisted root, nested under hoisted parent, .lpm/nested) so
        // we never have to reverse-engineer the layout.
        let locations: Vec<&MaterializedPackage> = link_result
            .materialized
            .iter()
            .filter(|m| m.name == name && m.version == version)
            .collect();

        let applied = patch_engine::apply_patch(
            &locations,
            &patch_file,
            &entry.original_integrity,
            store,
            &name,
            &version,
        )?;

        // Surface a per-package debug breadcrumb so users running with
        // `RUST_LOG=debug` can see the patch pass without parsing JSON.
        // Production output stays on the post-install summary block.
        let total_files = applied.files_modified + applied.files_added + applied.files_deleted;
        tracing::debug!(
            "patch applied: {name}@{version} → {} location(s), {total_files} file(s)",
            applied.locations_patched.len()
        );
        let _ = json_output; // suppress unused — we read it for symmetry only
        results.push(applied);
    }

    Ok(results)
}

/// Returns the number of symlinks created.
fn link_workspace_members(
    project_dir: &Path,
    members: &[WorkspaceMemberLink],
) -> Result<usize, LpmError> {
    if members.is_empty() {
        return Ok(0);
    }

    let node_modules = project_dir.join("node_modules");
    std::fs::create_dir_all(&node_modules).map_err(LpmError::Io)?;

    let mut linked = 0usize;
    for member in members {
        lpm_linker::link_workspace_member(&node_modules, &member.name, &member.source_dir)
            .map_err(|e| {
                LpmError::Workspace(format!(
                    "failed to link workspace member {}: {e}",
                    member.name
                ))
            })?;
        linked += 1;
    }
    Ok(linked)
}

/// Lightweight representation of a resolved package for the install pipeline.
/// Used both for fresh resolution results and lockfile-restored packages.
#[derive(Debug, Clone)]
struct InstallPackage {
    name: String,
    version: String,
    /// Source registry for lockfile
    source: String,
    /// Dependencies: (dep_name_in_parent, dep_version). The name is the
    /// LOCAL label THIS package uses for the dep in its own `package.json`
    /// (what the linker will create as the `node_modules/<name>/` symlink);
    /// for Phase 40 P2 npm-alias edges it diverges from the child's
    /// canonical registry name, and the alias target is recorded in
    /// `aliases` below.
    dependencies: Vec<(String, String)>,
    /// **Phase 40 P2** — per-package npm-alias edges:
    /// `local_name → target_canonical_name`. Empty unless this package
    /// declares aliased deps. Only surface aliases whose edge survived
    /// resolution (not platform-skipped) so the linker's dep-walk and
    /// the lockfile writer see identical sets.
    aliases: HashMap<String, String>,
    /// **Phase 40 P2** — explicit root-symlink filenames for this
    /// package. `None` preserves the pre-P2 "use pkg.name if
    /// is_direct" behavior. `Some(vec)` drives Phase 3 of the linker
    /// directly. Populated by `resolved_to_install_packages` from the
    /// resolver's `root_aliases` map so the linker can build
    /// `node_modules/<local>/` for aliased root deps (and the rare
    /// dual-reference case where the same resolved `(name, version)`
    /// is root-referenced both canonically AND by one or more
    /// aliases).
    root_link_names: Option<Vec<String>>,
    /// Whether this is a direct dependency of the root project
    is_direct: bool,
    /// Whether this is an LPM package (for tarball fetching)
    is_lpm: bool,
    /// SRI integrity hash for verification (e.g. "sha512-...")
    integrity: Option<String>,
    /// Tarball URL from resolution — avoids re-fetching metadata during download.
    tarball_url: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_with_options(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    offline: bool,
    force: bool,
    allow_new: bool,
    linker_override: Option<&str>,
    no_skills: bool,
    no_editor_setup: bool,
    no_security_summary: bool,
    auto_build: bool,
    // Phase 32 Phase 2: when invoked from the workspace-aware install path,
    // the list of `package.json` files that were modified before this call.
    // Surfaced in the JSON output as `target_set` so agents can see which
    // workspace members were touched. `None` for legacy/standalone callers.
    target_set: Option<&[String]>,
    // Phase 33 audit Finding 1 fix: when `Some`, the install pipeline
    // populates the map with `name → resolved_version` for every DIRECT
    // dependency. Used by `run_add_packages` and `run_install_filtered_add`
    // to feed `finalize_packages_in_manifest` without doing a flat scan
    // over the lockfile (which can't distinguish direct from transitive
    // when the same name appears at different versions). Non-Phase-33
    // callers pass `None`.
    direct_versions_out: Option<&mut HashMap<String, lpm_semver::Version>>,
) -> Result<(), LpmError> {
    if !json_output {
        output::print_header();
    }

    let start = Instant::now();

    // Step 1: Read package.json
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "no package.json found in current directory".to_string(),
        ));
    }

    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;

    // Fast-exit: if package.json + lockfile haven't changed and node_modules
    // is intact, skip the entire install pipeline. Two stats + one read + one
    // SHA-256 hash ≈ 1-2ms vs 82ms for a full warm install.
    // --force bypasses this check to force a full re-install.
    //
    // Phase 34.1: uses the shared install_state predicate (single source of truth).
    let install_state = crate::install_state::check_install_state(project_dir);
    if !force && !offline && install_state.up_to_date {
        let elapsed = start.elapsed();
        let total_ms = elapsed.as_millis();
        if json_output {
            // Emit the same `timing` object shape as the main and offline paths
            // so benchmark scripts can parse install output uniformly regardless
            // of which fast-path was taken. Stages are zero because no real work
            // ran — the entire pipeline was skipped.
            let mut json = serde_json::json!({
                "success": true,
                "up_to_date": true,
                "duration_ms": total_ms as u64,
                "timing": {
                    "resolve_ms": 0u128,
                    "fetch_ms": 0u128,
                    "link_ms": 0u128,
                    "total_ms": total_ms,
                },
            });
            // Phase 2: surface workspace target set for agents.
            if let Some(targets) = target_set {
                json["target_set"] = serde_json::Value::Array(
                    targets.iter().map(|s| serde_json::json!(s)).collect(),
                );
            }
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            // Header already printed at function entry.
            output::success(&format!("up to date ({total_ms}ms)"));
        }
        return Ok(());
    }

    let pkg_name = pkg.name.as_deref().unwrap_or("(unnamed)");
    if !json_output {
        output::info(&format!("Installing dependencies for {}", pkg_name.bold()));
    }

    // Phase 43 — shared gate counters. Populated by the lockfile
    // fast path (Change 1) when a stored URL fails the scheme/shape/
    // origin gate, and (in follow-up commits) by the stale-URL retry
    // path. Surfaced on `timing.fetch_breakdown.tarball_url_gate`.
    let gate_stats = Arc::new(GateStats::default());

    let mut deps = pkg.dependencies.clone();

    // `lpm install` resolves BOTH `dependencies` and `devDependencies`,
    // matching npm/pnpm/yarn semantics. Pre-2026-04-16 only `dependencies`
    // flowed through the pipeline, which silently no-op'd `lpm install -D`
    // (the spec landed in the manifest but was never resolved or linked).
    //
    // Conflict rule: `dependencies` wins. npm treats the same key in both
    // sections as malformed, and `dependencies` is the production contract —
    // it should never be shadowed by a dev-only entry.
    //
    // `lpm deploy` strips `devDependencies` from the output manifest before
    // re-entering this path, so the deploy closure stays prod-only. An
    // explicit `--prod` / `--omit dev` surface for `lpm install` itself is
    // tracked for a future phase, not hardcoded here.
    for (name, range) in &pkg.dev_dependencies {
        deps.entry(name.clone()).or_insert_with(|| range.clone());
    }

    // Resolve `catalog:` protocols and EXTRACT `workspace:*` member references
    // before anything else (lockfile fast path, resolver). This ensures the
    // `deps` HashMap contains only real registry ranges by the time the
    // resolver sees it.
    //
    // **Phase 32 Phase 2 audit fix #3 (workspace:^ resolver bug):** previously
    // we called `lpm_workspace::resolve_workspace_protocol` which rewrote
    // `"@scope/member": "workspace:^"` to `"@scope/member": "^1.5.0"` and
    // LEFT IT in `deps`. The resolver then tried to fetch
    // `@scope/member@^1.5.0` from npm/lpm.dev and 404'd against the upstream
    // proxy, because unpublished workspace members can't be looked up
    // remotely. Post-fix, we strip workspace member references from `deps`
    // entirely; they are linked from disk after the install pipeline
    // finishes via [`link_workspace_members`].
    //
    // Catalog resolution must use the workspace ROOT catalogs when inside a
    // workspace, because workspace members define `"catalog:"` references
    // that point to centralized version definitions in the root package.json.
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .ok()
        .flatten();

    let workspace_member_deps: Vec<WorkspaceMemberLink> = if let Some(ref ws) = workspace {
        // workspace:* extraction (NEW: replaces resolve_workspace_protocol)
        let extracted = extract_workspace_protocol_deps(&mut deps, ws)?;
        if !extracted.is_empty() && !json_output {
            for member in &extracted {
                tracing::debug!(
                    "workspace member (local): {} @ {} from {}",
                    member.name,
                    member.version,
                    member.source_dir.display()
                );
            }
        }

        // catalog: protocol — resolve from workspace root catalogs
        if !ws.root_package.catalogs.is_empty() {
            match lpm_workspace::resolve_catalog_protocol(&mut deps, &ws.root_package.catalogs) {
                Ok(resolved) => {
                    if !resolved.is_empty() && !json_output {
                        for (name, _orig, ver) in &resolved {
                            tracing::debug!("catalog: {name} → {ver}");
                        }
                    }
                }
                Err(e) => {
                    return Err(LpmError::Registry(format!(
                        "catalog resolution failed: {e}"
                    )));
                }
            }
        }
        extracted
    } else {
        // Standalone project (no workspace): no workspace member deps possible.
        // Local catalogs are still resolved if present.
        if !pkg.catalogs.is_empty() {
            match lpm_workspace::resolve_catalog_protocol(&mut deps, &pkg.catalogs) {
                Ok(resolved) => {
                    if !resolved.is_empty() && !json_output {
                        for (name, _orig, ver) in &resolved {
                            tracing::debug!("catalog: {name} → {ver}");
                        }
                    }
                }
                Err(e) => {
                    return Err(LpmError::Registry(format!(
                        "catalog resolution failed: {e}"
                    )));
                }
            }
        }
        Vec::new()
    };

    // **Phase 32 Phase 5** — fully parse and validate the override set
    // up-front (fail-closed). This runs BEFORE the empty-deps
    // short-circuit so a malformed override is surfaced even when
    // the project has zero dependencies — otherwise users would only
    // discover the validation failure after adding their first dep.
    //
    // The three sources are merged through the resolver's parser. Any
    // malformed selector, target, or multi-segment path is a HARD
    // ERROR here, surfaced to the user as a clear validation message.
    //
    // - `lpm.overrides` (LPM-native, wins on conflict)
    // - `overrides`     (npm-standard, top-level)
    // - `resolutions`   (yarn-style alias for overrides)
    let lpm_overrides_map = pkg
        .lpm
        .as_ref()
        .map(|l| l.overrides.clone())
        .unwrap_or_default();
    let override_set = OverrideSet::parse(&lpm_overrides_map, &pkg.overrides, &pkg.resolutions)
        .map_err(|e| LpmError::Script(format!("invalid override in package.json: {e}")))?;

    if deps.is_empty() && workspace_member_deps.is_empty() {
        // Phase 32 Phase 2 audit fix: emit a proper JSON object even on the
        // empty-deps short-circuit so agents driving install always get a
        // parseable result. Pre-fix this branch returned silently in JSON
        // mode, which combined with the workspace-aware filtered install
        // path produced a complete output silence on fresh workspaces.
        let elapsed = start.elapsed();
        let total_ms = elapsed.as_millis();
        if json_output {
            let mut json = serde_json::json!({
                "success": true,
                "no_dependencies": true,
                "duration_ms": total_ms as u64,
                "timing": {
                    "resolve_ms": 0u128,
                    "fetch_ms": 0u128,
                    "link_ms": 0u128,
                    "total_ms": total_ms,
                },
            });
            if let Some(targets) = target_set {
                json["target_set"] = serde_json::Value::Array(
                    targets.iter().map(|s| serde_json::json!(s)).collect(),
                );
            }
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            output::success("No dependencies to install");
        }
        // **Phase 32 Phase 5** — clean up stale overrides-state.json
        // when the user removes all overrides from a no-dep project.
        // We can't write a fresh state because there are no overrides,
        // and a stale state would cause `lpm graph --why` to surface
        // ghost trace data. Mirrors the same logic in the main path.
        if override_set.is_empty()
            && overrides_state::read_state(project_dir).is_some()
            && let Err(e) = overrides_state::delete_state(project_dir)
        {
            tracing::warn!("failed to delete stale overrides-state.json: {e}");
        }
        return Ok(());
    }

    // **Phase 32 Phase 5** — read the persisted override state and
    // compute whether the override set has drifted since the last
    // recorded install. This MUST run BEFORE the `--offline` branch
    // so that:
    //
    // 1. **Online mode** can drop the lockfile fast path on drift and
    //    force a fresh resolve.
    // 2. **Offline mode** can hard-error on drift (since it can't
    //    re-resolve) and can write/delete the state file alongside
    //    the link step.
    //
    // **Audit fix (2026-04-12, GPT-5.4 end-to-end audit).** Pre-fix,
    // these two lines lived AFTER the offline branch's `return`
    // statement, so the offline path silently shadowed override
    // edits, never wrote a state file, and never cleaned up stale
    // state. Three regression tests in
    // `tests/overrides_phase5_regression.rs::cli_offline_install_*`
    // pin the contract end-to-end against the built binary.
    let prior_overrides_state = overrides_state::read_state(project_dir);
    let overrides_changed = prior_overrides_state
        .as_ref()
        .map(|s| s.fingerprint != override_set.fingerprint())
        .unwrap_or(!override_set.is_empty());
    if overrides_changed {
        tracing::debug!(
            "overrides changed since last install (fingerprint drift) — \
             invalidating lockfile fast path"
        );
    }

    // **Phase 32 Phase 6 — `lpm.patchedDependencies`.**
    // Mirror of the Phase 5 overrides drift detection. Patches must be
    // checked BEFORE the offline branch so:
    //   1. Online mode can drop the lockfile fast path on drift and
    //      force a fresh resolve (the patches themselves don't affect
    //      resolution, but a re-applied patch is required after any
    //      re-link).
    //   2. Offline mode can hard-error on drift since it can't
    //      re-resolve to bring the lockfile in sync.
    let current_patches: HashMap<String, PatchedDependencyEntry> = pkg
        .lpm
        .as_ref()
        .map(|l| l.patched_dependencies.clone())
        .unwrap_or_default();
    let current_patch_fingerprint = patch_state::compute_fingerprint(&current_patches);
    let prior_patch_state = patch_state::read_state(project_dir);
    let patches_changed = prior_patch_state
        .as_ref()
        .map(|s| s.fingerprint != current_patch_fingerprint)
        .unwrap_or(!current_patches.is_empty());
    if patches_changed {
        tracing::debug!(
            "patches changed since last install (fingerprint drift) — \
             invalidating lockfile fast path"
        );
    }

    // Determine linker mode early: CLI flag > package.json config > default (isolated)
    let linker_mode = linker_override
        .or_else(|| pkg.lpm.as_ref().and_then(|l| l.linker.as_deref()))
        .map(|s| match s {
            "hoisted" => lpm_linker::LinkerMode::Hoisted,
            _ => lpm_linker::LinkerMode::Isolated,
        })
        .unwrap_or(lpm_linker::LinkerMode::Isolated);

    // Step 2: Try lockfile fast path, else resolve
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let arc_client = Arc::new(client.clone_with_config());

    // Offline mode: require lockfile, no network
    if offline {
        // **Phase 32 Phase 5 — audit fix #2 (2026-04-12).** Offline
        // mode cannot re-resolve, so any fingerprint drift is
        // unsafe: the lockfile would silently shadow the user's
        // override edits. Refuse with a clear, actionable message
        // that tells the user how to recover.
        if overrides_changed {
            let detail = match prior_overrides_state.as_ref() {
                Some(prior) => format!(
                    "previous fingerprint {} differs from current {}",
                    prior.fingerprint,
                    override_set.fingerprint()
                ),
                None if !override_set.is_empty() => {
                    "no previously-recorded override fingerprint; the lockfile may have \
                     been generated without these overrides"
                        .to_string()
                }
                None => "override state inconsistency".to_string(),
            };
            return Err(LpmError::Registry(format!(
                "--offline: override set differs from the lockfile's recorded set ({detail}). \
                 Run `lpm install` (online) to re-resolve, then retry --offline."
            )));
        }

        // **Phase 32 Phase 6** — same hard-error semantics for the
        // patch set. Offline mode can't re-resolve OR re-fetch a
        // possibly-changed store baseline, so any drift in the
        // declared patch set leaves the install in an unknown state.
        if patches_changed {
            let detail = match prior_patch_state.as_ref() {
                Some(prior) => format!(
                    "previous fingerprint {} differs from current {}",
                    prior.fingerprint, current_patch_fingerprint
                ),
                None if !current_patches.is_empty() => {
                    "no previously-recorded patch fingerprint; the lockfile may have \
                     been written without these patches"
                        .to_string()
                }
                None => "patch state inconsistency".to_string(),
            };
            return Err(LpmError::Registry(format!(
                "--offline: lpm.patchedDependencies differs from the previously-recorded \
                 patch set ({detail}). Run `lpm install` (online) to re-resolve, then retry \
                 --offline."
            )));
        }

        let locked = try_lockfile_fast_path(&lockfile_path, &deps, client, &gate_stats)
            .ok_or_else(|| {
                LpmError::Registry(
                    "--offline requires a lockfile. Run `lpm install` online first.".into(),
                )
            })?
            .packages; // Offline mode skips the writeback machinery —
        // no fetch happens, no URLs diverge, and any v1
        // → v2 binary migration is deferred to the next
        // online install (intentional — `--offline` is
        // the "don't touch anything remote" mode).
        if !json_output {
            output::info(&format!(
                "Offline: using lockfile ({} packages)",
                locked.len().to_string().bold()
            ));
        }

        // Verify all packages are in the global store
        let store = PackageStore::default_location()?;
        let mut missing = Vec::new();
        for p in &locked {
            if !store.has_package(&p.name, &p.version) {
                missing.push(format!("{}@{}", p.name, p.version));
            }
        }
        if !missing.is_empty() {
            return Err(LpmError::Registry(format!(
                "--offline: {} package(s) not in global store: {}",
                missing.len(),
                missing[..missing.len().min(5)].join(", ")
            )));
        }

        // **Phase 32 Phase 5 — state file lifecycle in offline mode
        // (2026-04-12).** Reaching this point means the fingerprint
        // check above passed — i.e., the on-disk state file matches
        // the current parsed override set, OR both sides are empty.
        // Two sub-cases:
        //
        // - **Both empty** (`prior` is `None`, `current.is_empty()`):
        //   no state file exists and none should — nothing to do.
        // - **Both have the SAME non-empty fingerprint**: the state
        //   file is already correct; preserving it across an offline
        //   install matches what `lpm graph --why` consumers expect.
        //
        // We do NOT rewrite the state file here. The `applied` trace
        // belongs to the most recent FRESH resolution; offline mode
        // never re-resolves and would produce an empty trace, which
        // would be a regression for `graph --why`. Preserving the
        // existing trace is correct.
        //
        // The "user removed all overrides offline" cleanup case is
        // handled UPSTREAM by the fingerprint hard-error: removing
        // overrides flips the fingerprint, which trips the
        // `overrides_changed` branch above, returning a clear
        // "re-resolve online" error.

        // Go directly to link step (skip resolution and download)
        return run_link_and_finish(
            client,
            project_dir,
            &deps,
            &pkg,
            locked,
            0,
            0,
            true,
            json_output,
            start,
            linker_mode,
            force,
            &workspace_member_deps,
        )
        .await;
    }

    // --force skips lockfile fast path to force fresh resolution from registry.
    // --overrides-changed also skips it (Phase 32 Phase 5).
    // --patches-changed also skips it (Phase 32 Phase 6) — re-applying a
    // patch that's been added or moved since the last install requires
    // a clean re-link from store before the patch engine runs, and the
    // lockfile fast path bypasses linker work.
    let lockfile_result = if force || overrides_changed || patches_changed {
        None
    } else {
        try_lockfile_fast_path(&lockfile_path, &deps, client, &gate_stats)
    };
    // **Phase 32 Phase 5** — applied-override trace for the rest of the
    // install pipeline. Empty for the lockfile-fast-path branch (we
    // preserve the previously-recorded trace from disk in that case);
    // populated for fresh resolution from the resolver's apply log.
    let mut applied_overrides: Vec<OverrideHit> = Vec::new();

    // Phase 38 P3: fetch semaphore hoisted out of the fetch loop so the
    // optional speculative dispatcher can share the 16-permit download
    // pool with the post-resolve real-fetch loop. Without sharing, a
    // spec dispatcher racing 16 downloads alongside the later real loop's
    // 16 would saturate the network for no wall-clock win. One pool,
    // used first by speculation, then drained by real fetch.
    let fetch_semaphore = Arc::new(Semaphore::new(max_concurrent_downloads()));
    // Phase 38 P3: also hoist the `PackageStore` so the speculative
    // dispatcher can write tarballs into the real store during the
    // resolve phase. Post-resolve, the fetch loop rebinds to the same
    // handle (cheap Arc-style clone underneath).
    let store = PackageStore::default_location()?;

    // Phase 38 P3 speculative fetch. Default on since Phase 39 P0; set
    // `LPM_SPEC_FETCH=0` to disable (kept as an escape hatch in case a
    // particular tree shape or network regresses against the default).
    // Strictly additive when on — worst case a version mismatch wastes
    // one tarball per root; the real fetch loop still resolves correctly.
    let spec_fetch_enabled = std::env::var("LPM_SPEC_FETCH")
        .map(|v| v != "0")
        .unwrap_or(true);

    // P3 stats — filled by the speculative dispatcher when engaged.
    let mut spec_stats = SpeculativeStats::default();

    // Phase 39 P2: shared fetch coordinator — serializes per-key fetch
    // work across the speculative dispatcher and the real fetch loop
    // now that the drain-wait between them is gone.
    let fetch_coord: Arc<FetchCoordinator> = Arc::new(FetchCoordinator::default());

    // Phase 39 P2: speculation join handle hoisted out of the fresh-
    // resolve match arm so the main task can drain it AFTER the real
    // fetch loop completes (instead of before). Concurrent tarball
    // downloads overlap the fetch loop instead of serializing ahead of it.
    let mut speculation_join: Option<SpeculativeJoin> = None;

    // Phase 40 P3a — substage breakdown of cold-resolve wall-clock.
    // Captured here (outside the fresh/warm branch) so the JSON output
    // code path can surface a consistent shape whether the lockfile
    // fast path kicked in or not. Zeros on lockfile-fast-path;
    // populated from the resolver on fresh resolution.
    let mut initial_batch_ms: u128 = 0;
    let mut resolver_stage_timing = lpm_resolver::StageTiming::default();

    // Phase 43 — stash the parsed lockfile + `needs_binary_upgrade`
    // flag from the fast path so the writeback step at install-end
    // can patch + re-emit it. `None` on fresh-resolve branches (the
    // resolver builds its own lockfile via `resolved_to_install_packages`
    // and the writer at install-end already handles that case).
    let mut fast_path_lockfile: Option<lpm_lockfile::Lockfile> = None;
    let mut needs_binary_upgrade = false;

    let (mut packages, resolve_ms, used_lockfile, platform_skipped) = match lockfile_result {
        Some(fast_path) => {
            if !json_output {
                output::info(&format!(
                    "Using lockfile ({} packages)",
                    fast_path.packages.len().to_string().bold()
                ));
            }
            fast_path_lockfile = Some(fast_path.lockfile);
            needs_binary_upgrade = fast_path.needs_binary_upgrade;
            (fast_path.packages, 0u128, true, 0usize)
        }
        None => {
            let resolve_start = Instant::now();
            let spinner = make_spinner("Resolving dependency tree...");

            // Batch prefetch: warm the metadata cache for all root deps in one request.
            // This turns 70+ sequential HTTP requests into 1-3 batch requests.
            // Skip if all root deps are already in the metadata cache (warm install).
            let dep_names: Vec<String> = deps.keys().cloned().collect();
            let cache_has_all = dep_names.iter().all(|name| {
                let cache_key = if name.starts_with("@lpm.dev/") {
                    format!("lpm:{name}")
                } else {
                    format!("npm:{name}")
                };
                // Check if metadata cache file exists and is fresh
                let cache_dir =
                    dirs::home_dir().map(|h| h.join(".lpm").join("cache").join("metadata"));
                cache_dir
                    .and_then(|dir| {
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(cache_key.as_bytes());
                        let hash = format!("{:x}", hasher.finalize());
                        let path = dir.join(&hash[..16]);
                        let modified = path.metadata().ok()?.modified().ok()?;
                        let age = std::time::SystemTime::now().duration_since(modified).ok()?;
                        Some(age < std::time::Duration::from_secs(300))
                    })
                    .unwrap_or(false)
            });

            // Phase 34.5: capture batch results to pass in-memory to resolver.
            // This avoids 52+ disk reads during resolution (HMAC + MessagePack deser each).
            let mut prefetched_batch = None;

            if !dep_names.is_empty() && !cache_has_all {
                // Single deep batch: server resolves transitive deps recursively
                // (up to 3 levels), returning ALL metadata in one round-trip.
                // This replaces the 3 sequential wave calls.
                //
                // Phase 38 P3 (default on): route through the streaming
                // variant and attach a speculative dispatcher that starts
                // tarball downloads as root manifests arrive. Phase 39 P2
                // removes the drain-wait that used to block the fetch
                // loop — the speculation handle propagates to the outer
                // scope and is drained AFTER fetch completes. The fetch
                // coordinator prevents duplicate downloads during the
                // overlap window.
                let batch_start = Instant::now();
                let batch_result = if spec_fetch_enabled {
                    match run_deep_batch_with_speculation(
                        &arc_client,
                        &store,
                        &fetch_semaphore,
                        &fetch_coord,
                        &deps,
                        &dep_names,
                    )
                    .await
                    {
                        Ok((batch, join)) => {
                            speculation_join = Some(join);
                            Ok(batch)
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    arc_client.batch_metadata_deep(&dep_names).await
                };
                // Phase 40 P3a — record the initial batch wall-clock
                // (request + parse + cache write) so the JSON output
                // can separate it from follow-up RPCs fired during
                // the pubgrub walk. Captured on both success AND
                // error paths: a batch that failed still paid its
                // observable cost and should show up in the
                // breakdown.
                initial_batch_ms = batch_start.elapsed().as_millis();
                match batch_result {
                    Ok(batch) => {
                        tracing::debug!(
                            "batch prefetch (deep): {} total packages cached in {}ms",
                            batch.len(),
                            initial_batch_ms
                        );
                        prefetched_batch = Some(batch);
                    }
                    Err(e) => {
                        // Non-fatal: resolver will fetch individually as fallback,
                        // but this is a significant performance regression (1 request → 50+).
                        // Warn so users/CI can diagnose slow installs.
                        tracing::warn!(
                            "batch prefetch failed, falling back to sequential resolution (slower): {e}"
                        );
                        if !json_output {
                            output::warn(
                                "Batch prefetch failed — falling back to sequential resolution (this will be slower).",
                            );
                        }
                    }
                }
            }

            let resolve_result = resolve_with_prefetch(
                arc_client.clone(),
                deps.clone(),
                override_set.clone(),
                prefetched_batch,
            )
            .await
            .map_err(|e| LpmError::Registry(format!("resolution failed: {e}")))?;

            // Phase 39 P2: drain-wait removed. `speculation_join` is
            // preserved on the outer scope and drained AFTER the fetch
            // loop below, so speculative tarball downloads can overlap
            // the real fetch loop (straggling specs race with the real
            // fetches for the same 24-permit download pool). The
            // `fetch_coord` serializes per-(name, version) work, so a
            // real fetch for a package spec is still downloading just
            // waits on the coord's per-key lock and returns as soon as
            // spec's atomic-rename makes it visible.
            let ms = resolve_start.elapsed().as_millis();
            spinner.stop(format!("Resolved in {ms}ms"));

            // Post-resolution peer dependency check: warn about unmet peers
            // using each package's actual selected version (not a union).
            let peer_warnings = check_unmet_peers(&resolve_result.packages, &resolve_result.cache);
            if !peer_warnings.is_empty() && !json_output {
                for w in &peer_warnings {
                    output::warn(&format!("peer dep: {w}"));
                }
            }

            // **Phase 32 Phase 5** — capture the override apply trace
            // from this fresh resolution. We surface it to the install
            // summary, the JSON output, and `.lpm/overrides-state.json`.
            applied_overrides = resolve_result.applied_overrides.clone();

            // **Phase 40 P1** — capture the platform-filtered optional
            // skip count. Surfaced as `timing.resolve.platform_skipped`
            // in `--json` output.
            let platform_skipped = resolve_result.platform_skipped;

            // **Phase 40 P3a** — capture the resolver substage
            // breakdown. Combined with the `initial_batch_ms`
            // measurement above, these feed the cold-resolve
            // observability story in `timing.resolve.*`.
            resolver_stage_timing = resolve_result.stage_timing;

            let packages = resolved_to_install_packages(
                &resolve_result.packages,
                &deps,
                &resolve_result.root_aliases,
            );

            if !json_output {
                output::info(&format!(
                    "Resolved {} packages ({}ms)",
                    packages.len().to_string().bold(),
                    ms
                ));
            }
            (packages, ms, false, platform_skipped)
        }
    };

    // Step 3: Download & store (parallel). Phase 38 P3: `store` is
    // already bound above — speculative dispatcher writes into it
    // during resolve, so by the time we reach here the store may hold
    // tarballs the `has_package` loop below picks up as cache hits.
    let fetch_start = Instant::now();

    // Phase 43 — aggregation buffer for the generalized writeback.
    // Populated inside the fetch block with every (name, version) →
    // final-URL pair (only when the final URL diverges from the
    // stored lockfile URL). Consumed at install-end to trigger a
    // lockfile rewrite. Hoisted out of the fetch block so the
    // writeback logic (below the block) can see it.
    let mut fresh_urls: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();

    // Phase 39 P2b: build link_targets up front so the event-driven
    // path can start per-package linking as each tarball lands.
    // `LinkTarget` fields don't depend on fetch completion — just on
    // resolver output — so building them here is safe. Reused by both
    // the event-driven and serial link paths.
    let link_targets: Vec<LinkTarget> = packages
        .iter()
        .map(|p| LinkTarget {
            name: p.name.clone(),
            version: p.version.clone(),
            store_path: store.package_dir(&p.name, &p.version),
            dependencies: p.dependencies.clone(),
            aliases: p.aliases.clone(),
            is_direct: p.is_direct,
            root_link_names: p.root_link_names.clone(),
        })
        .collect();

    // Phase 39 P2b: event-driven link mode. Per-package Phase 1+2 work
    // runs inside the fetch pipeline (parallel with tarball downloads
    // of other packages). Phase 3+3.5+4 run as a final batch. Default
    // on for the isolated linker; `LPM_SERIAL_LINK=1` reverts to the
    // single-shot `link_packages` path. Hoisted linker always uses
    // the serial path — it has a different layout model and isn't the
    // hot path for the default `lpm install`.
    let serial_link = std::env::var("LPM_SERIAL_LINK")
        .map(|v| v == "1")
        .unwrap_or(false);
    let event_driven_link = !serial_link && matches!(linker_mode, lpm_linker::LinkerMode::Isolated);

    // Phase 39 P2b: collection of per-package link handles. Cached
    // packages push into this before the fetch loop; fetch tasks push
    // as each tarball materializes. Awaited during the link-finalize
    // step below (post-fetch).
    let mut event_link_handles: Vec<
        tokio::task::JoinHandle<
            Result<(MaterializedPackage, lpm_linker::OnePackageResult), LpmError>,
        >,
    > = Vec::new();

    // Phase 39 P2b: stale-entry cleanup runs once, up front — must
    // happen before any per-pkg link spawn touches `.lpm/` so the
    // `read_dir` scan sees a stable snapshot.
    if event_driven_link {
        lpm_linker::cleanup_stale_entries(project_dir, &link_targets)?;
    }

    let mut to_download = Vec::new();
    let mut cached = 0usize;

    for p in &packages {
        // --force: re-download everything to verify integrity against registry,
        // even if the store already has it. The store's extract-to-temp + atomic
        // rename handles the case where the existing entry is valid.
        if !force && store.has_package(&p.name, &p.version) {
            cached += 1;
            // Phase 39 P2b: spawn per-pkg link task immediately — this
            // package is already materialized in the store, so Phase 1
            // can run in parallel with the fetch loop below.
            if event_driven_link {
                let target = LinkTarget {
                    name: p.name.clone(),
                    version: p.version.clone(),
                    store_path: store.package_dir(&p.name, &p.version),
                    dependencies: p.dependencies.clone(),
                    aliases: p.aliases.clone(),
                    is_direct: p.is_direct,
                    root_link_names: p.root_link_names.clone(),
                };
                let pd = project_dir.to_path_buf();
                let force_flag = force;
                event_link_handles.push(tokio::task::spawn_blocking(move || {
                    lpm_linker::link_one_package(&pd, &target, force_flag)
                }));
            }
        } else {
            to_download.push(p.clone());
        }
    }

    // Enforce minimumReleaseAge: block recently published packages unless --allow-new.
    // Only checked during fresh resolution (not lockfile fast path) because metadata
    // was already fetched and cached by the resolver — re-fetching hits the 5-min TTL cache.
    if !allow_new && !used_lockfile {
        let policy =
            lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));
        if policy.minimum_release_age_secs > 0 {
            let mut too_new = Vec::new();
            for p in &packages {
                // Look up the publish timestamp from the metadata cache.
                // During fresh resolution the resolver already fetched all metadata,
                // so these calls hit the local cache (no extra network round-trips).
                let publish_time = if p.is_lpm {
                    lpm_common::PackageName::parse(&p.name)
                        .ok()
                        .and_then(|pkg_name| {
                            // This will hit the TTL cache (< 5 min since resolution)
                            tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current()
                                    .block_on(arc_client.get_package_metadata(&pkg_name))
                            })
                            .ok()
                        })
                        .and_then(|meta| meta.time.get(&p.version).cloned())
                } else {
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current()
                            .block_on(arc_client.get_npm_package_metadata(&p.name))
                    })
                    .ok()
                    .and_then(|meta| meta.time.get(&p.version).cloned())
                };

                if let Some(warning) = policy.check_release_age(publish_time.as_deref()) {
                    let remaining = warning.minimum.saturating_sub(warning.age_secs);
                    let hours = remaining / 3600;
                    let minutes = (remaining % 3600) / 60;
                    too_new.push((p.name.clone(), p.version.clone(), hours, minutes));
                }
            }

            if !too_new.is_empty() {
                if !json_output {
                    output::warn(&format!(
                        "{} package(s) blocked by minimumReleaseAge ({}s):",
                        too_new.len(),
                        policy.minimum_release_age_secs,
                    ));
                    for (name, version, hours, minutes) in &too_new {
                        eprintln!(
                            "    {}@{} — {}h {}m remaining",
                            name, version, hours, minutes
                        );
                    }
                    eprintln!(
                        "  Use {} to install anyway, or add {} to package.json to disable.",
                        "--allow-new".bold(),
                        "\"lpm\": { \"minimumReleaseAge\": 0 }".dimmed(),
                    );
                }
                return Err(LpmError::Registry(format!(
                    "{} package(s) published too recently (minimumReleaseAge={}s). Use --allow-new to override.",
                    too_new.len(),
                    policy.minimum_release_age_secs,
                )));
            }
        }
    }

    let downloaded = to_download.len();
    // Phase 38 P0: accumulate per-task timings across the parallel pool so we
    // can emit a proper fetch-stage breakdown in `lpm install --json`. Empty
    // breakdown on the cached-everything path; filled in below when work runs.
    let mut fetch_breakdown = FetchBreakdown::default();
    // Phase 38 P1: streaming fetch fast path — bytes flow from reqwest
    // through a `StreamReader` + `SyncIoBridge` into a sync hash+extract
    // pipeline in `spawn_blocking`, no temp file. Default on since
    // Phase 39 P0; set `LPM_STREAM_FETCH=0` to fall back to the legacy
    // temp-file spool (kept as an escape hatch for debugging fetch
    // regressions or non-sha512 integrity edge cases).
    let streaming_fetch = std::env::var("LPM_STREAM_FETCH")
        .map(|v| v != "0")
        .unwrap_or(true);
    if !to_download.is_empty() {
        let overall = ProgressBar::new(to_download.len() as u64);
        overall.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} Downloading [{bar:30.cyan/dim}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("━╸─"),
        );
        overall.enable_steady_tick(std::time::Duration::from_millis(80));

        // Phase 38 P3: share the hoisted `fetch_semaphore` so speculative
        // dispatches (pre-resolve) and real fetches (post-resolve) draw
        // from the same 24-permit pool.
        let semaphore = fetch_semaphore.clone();
        let mut handles = Vec::new();

        for p in to_download {
            let sem = semaphore.clone();
            let client = arc_client.clone();
            let store_ref = store.clone();
            let coord = fetch_coord.clone();
            let overall = overall.clone();
            let force_flag = force;
            // Phase 39 P2b: per-task link scheduling captures.
            let event_link = event_driven_link;
            let project_dir_buf = project_dir.to_path_buf();
            // Phase 43 P43-2 — shared gate/retry counters for the
            // stale-URL recovery path in `fetch_and_store_*`.
            let gate_stats_c = gate_stats.clone();

            handles.push(tokio::spawn(async move {
                type LinkHandle = tokio::task::JoinHandle<
                    Result<(MaterializedPackage, lpm_linker::OnePackageResult), LpmError>,
                >;

                // P0 timing: spawn→key-lock→permit captures the full time this
                // task sat queued. Phase 39 P2: now also covers the
                // FetchCoordinator wait — if a speculation is mid-fetch for
                // the same `(name, ver)`, we wait on the per-key lock and
                // short-circuit via the store-hit check below.
                let queue_start = std::time::Instant::now();

                // Phase 39 P2: per-key fetch coordination. Acquired BEFORE
                // the download permit — if a sibling (speculation) is
                // already fetching this key, we wait here without consuming
                // a permit. On wake, `has_package` is true and we skip the
                // real fetch entirely (zero bandwidth, zero CPU).
                let key_lock = coord.lock_for(&p.name, &p.version).await;
                let _key_guard = key_lock.lock().await;

                // Spawn the per-pkg link task once the tarball is in the
                // store. Used in both the sibling-skip path and the normal
                // fetch path — in either case the package is materialized
                // by the time we call `link_one_package`.
                let spawn_link = |p: &InstallPackage| -> Option<LinkHandle> {
                    if !event_link {
                        return None;
                    }
                    let target = LinkTarget {
                        name: p.name.clone(),
                        version: p.version.clone(),
                        store_path: store_ref.package_dir(&p.name, &p.version),
                        dependencies: p.dependencies.clone(),
                        aliases: p.aliases.clone(),
                        is_direct: p.is_direct,
                        root_link_names: p.root_link_names.clone(),
                    };
                    let pd = project_dir_buf.clone();
                    Some(tokio::task::spawn_blocking(move || {
                        lpm_linker::link_one_package(&pd, &target, force_flag)
                    }))
                };

                // Phase 39 P2b: only honour the store-hit short-circuit when
                // NOT in `--force` mode. `--force` is the "re-verify
                // integrity against registry" path: the user explicitly
                // wants every tarball re-downloaded and re-hashed, even if
                // the store already has a valid copy. Without this gate, a
                // sibling task (or a prior install) making the store hot
                // would neuter `--force`.
                if !force_flag && store_ref.has_package(&p.name, &p.version) {
                    // A sibling completed the fetch while we waited on the
                    // key lock. Use the stored SRI for lockfile output;
                    // task_timings stays at defaults (no download work done
                    // on THIS task's critical path — the sibling's timings
                    // covered it). Phase 43: `None` for `final_url` here
                    // because THIS task didn't hit the registry — the
                    // sibling's task already reported the URL it used
                    // (via its own return value) and will be folded into
                    // the writeback aggregator. Reporting `None` avoids
                    // double-counting a divergence or conflicting on the
                    // URL value.
                    let sri = lpm_store::read_stored_integrity(
                        &store_ref.package_dir(&p.name, &p.version),
                    )
                    .unwrap_or_default();
                    let link_h = spawn_link(&p);
                    overall.inc(1);
                    return Ok::<
                        (
                            String,
                            String,
                            String,
                            TaskTimings,
                            Option<LinkHandle>,
                            Option<String>,
                        ),
                        LpmError,
                    >((
                        p.name.clone(),
                        p.version.clone(),
                        sri,
                        TaskTimings {
                            queue_wait_ms: queue_start.elapsed().as_millis(),
                            ..Default::default()
                        },
                        link_h,
                        None,
                    ));
                }

                let _permit = sem
                    .acquire()
                    .await
                    .map_err(|_| LpmError::Registry("download semaphore closed".into()))?;
                let queue_wait_ms = queue_start.elapsed().as_millis();

                overall.set_message(format!("{}@{}", p.name, p.version));

                let (computed_sri, task_timings, final_url) = if streaming_fetch {
                    fetch_and_store_streaming(
                        &client,
                        &store_ref,
                        &p,
                        queue_wait_ms,
                        &project_dir_buf,
                        &gate_stats_c,
                    )
                    .await?
                } else {
                    fetch_and_store_legacy(
                        &client,
                        &store_ref,
                        &p,
                        queue_wait_ms,
                        &project_dir_buf,
                        &gate_stats_c,
                    )
                    .await?
                };

                // Phase 39 P2b: spawn per-pkg link immediately — pkg is
                // now materialized. Runs on the blocking pool in parallel
                // with sibling fetch tasks still downloading.
                let link_h = spawn_link(&p);

                overall.inc(1);
                Ok::<
                    (
                        String,
                        String,
                        String,
                        TaskTimings,
                        Option<LinkHandle>,
                        Option<String>,
                    ),
                    LpmError,
                >((
                    p.name.clone(),
                    p.version.clone(),
                    computed_sri,
                    task_timings,
                    link_h,
                    Some(final_url),
                ))
            }));
        }

        // Collect computed integrity hashes and fold per-task timings into
        // the aggregate breakdown. Phase 43: `fresh_urls` aggregates
        // the URL that actually served bytes for each (name, version),
        // so the writeback step at install-end can detect divergence
        // from the stored lockfile URL (stale-URL recovery) or from
        // `None` (origin-mismatch rebase that on-demand-resolved a
        // fresh URL).
        let mut integrity_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for handle in handles {
            let (name, version, sri, timings, link_h, final_url) = handle
                .await
                .map_err(|e| LpmError::Registry(format!("download task panicked: {e}")))??;
            integrity_map.insert(format!("{name}@{version}"), sri);
            fetch_breakdown.record(timings);
            if let Some(lh) = link_h {
                event_link_handles.push(lh);
            }
            if let Some(url) = final_url {
                fresh_urls.insert((name, version), url);
            }
        }

        // Update packages with computed integrity hashes (for lockfile persistence)
        for p in &mut packages {
            let key = format!("{}@{}", p.name, p.version);
            if let Some(sri) = integrity_map.get(&key) {
                p.integrity = Some(sri.clone());
            }
            // Phase 43 — update `InstallPackage.tarball_url` to the
            // URL that actually served bytes so the fresh-resolve
            // writer (at install-end) persists it. For the fast-path
            // case, this flows into the generalized writeback (see
            // `compute_fresh_tarball_urls` at install-end).
            if let Some(url) = fresh_urls.get(&(p.name.clone(), p.version.clone())) {
                p.tarball_url = Some(url.clone());
            }
        }

        overall.finish_and_clear();
    }

    let fetch_ms = fetch_start.elapsed().as_millis();

    // Phase 39 P2: drain speculation AFTER the real fetch loop, not
    // before. Spec tarballs for correctly-predicted versions were
    // consumed by the fetch coord's per-key lock (real fetch waited on
    // them and short-circuited). What remains in-flight here is spec
    // work for WRONG-version predictions — harmless wasted bandwidth
    // that the resolver didn't want. We still await the dispatcher
    // handle so its atomics can be read into `spec_stats` for --json,
    // but it happens outside both `fetch_ms` and `link_ms` so stage
    // times are not inflated by wasted speculation tails.
    if let Some(join) = speculation_join.take() {
        join.drain(&mut spec_stats).await;
    }

    if !json_output {
        if downloaded > 0 {
            output::info(&format!(
                "Downloaded {} packages, {} from cache ({}ms)",
                downloaded.to_string().bold(),
                cached,
                fetch_ms
            ));
        } else {
            output::info(&format!("All {} packages from cache", cached));
        }
    }

    // Step 4: link_targets — already built before the fetch loop (Phase 39
    // P2b) so the event-driven path could dispatch per-pkg link work
    // during fetch. No-op here to keep the surrounding structure stable.
    let _ = &link_targets; // retained for downstream consumers below

    // Step 5: Link into node_modules
    let link_start = Instant::now();
    let spinner = make_spinner("Linking node_modules...");

    let link_result = if event_driven_link {
        // Phase 39 P2b: event-driven path. Per-pkg Phase 1+2 tasks were
        // spawned inside the fetch loop and for each cached package
        // before the loop; await them here, aggregate counters, then
        // run Phase 3+3.5+4 via `link_finalize`. `link_ms` measures
        // only the tail: any per-pkg link task still running past
        // `fetch_ms` plus the final finalize pass. Well-overlapped
        // installs show a near-zero link_ms.
        let mut linked_count = 0usize;
        let mut skipped_count = 0usize;
        let mut symlinked_count = 0usize;
        let mut materialized_all: Vec<MaterializedPackage> =
            Vec::with_capacity(event_link_handles.len());

        for lh in event_link_handles.drain(..) {
            let (m, r) = lh
                .await
                .map_err(|e| LpmError::Registry(format!("link task panicked: {e}")))??;
            materialized_all.push(m);
            if r.linked {
                linked_count += 1;
            } else {
                skipped_count += 1;
            }
            symlinked_count += r.symlinks_created;
        }

        let finalize = lpm_linker::link_finalize(project_dir, &link_targets, pkg.name.as_deref())?;
        symlinked_count += finalize.symlinks_created;

        LinkResult {
            linked: linked_count,
            symlinked: symlinked_count,
            bin_linked: finalize.bin_count,
            skipped: skipped_count,
            self_referenced: finalize.self_referenced,
            materialized: materialized_all,
        }
    } else {
        match linker_mode {
            lpm_linker::LinkerMode::Hoisted => lpm_linker::link_packages_hoisted(
                project_dir,
                &link_targets,
                force,
                pkg.name.as_deref(),
            )?,
            lpm_linker::LinkerMode::Isolated => {
                lpm_linker::link_packages(project_dir, &link_targets, force, pkg.name.as_deref())?
            }
        }
    };

    let link_ms = link_start.elapsed().as_millis();
    spinner.stop(format!("Linked in {link_ms}ms"));

    // Phase 32 Phase 2 audit fix #3: link workspace member dependencies AFTER
    // the regular linker run. The linker's stale-symlink cleanup pass at the
    // top of `link_packages` would otherwise wipe these symlinks on every
    // install (they're not in `direct_names` because workspace members were
    // stripped from `deps` before resolution by `extract_workspace_protocol_deps`).
    // Re-creating them here every time keeps the layout consistent.
    let workspace_links_created = link_workspace_members(project_dir, &workspace_member_deps)?;
    if workspace_links_created > 0 && !json_output {
        output::info(&format!(
            "Linked {} workspace member(s)",
            workspace_links_created.to_string().bold()
        ));
    }

    // **Phase 32 Phase 6 — `lpm patch` apply pass.**
    //
    // Run AFTER both the regular linker pass AND the workspace-member
    // linker pass, so every materialized destination is in place. Run
    // BEFORE the build-state capture (Phase 4) so the patched bytes
    // are what `lpm build` and `lpm approve-builds` see.
    //
    // Apply is unconditional even on the lockfile fast path: see the
    // module-level comment in `patch_engine.rs` for why.
    let applied_patches = apply_patches_for_install(
        &current_patches,
        &link_result,
        &store,
        project_dir,
        json_output,
    )?;

    // Step 6: Lifecycle script security audit + trusted script execution
    let policy = lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));

    // **Phase 32 Phase 4 M3:** capture the install-time blocked set into
    // `<project_dir>/.lpm/build-state.json` so that:
    //   1. `lpm approve-builds` doesn't have to re-walk the store on startup
    //   2. The post-install warning is suppressed when the blocked set is
    //      unchanged from the previous install (the spam-prevention rule)
    //   3. Agents driving install via JSON output get a structured
    //      `blocked_count` / `blocked_set_changed` summary
    let installed_with_integrity: Vec<(String, String, Option<String>)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
        .collect();
    // **Phase 46 P1 metadata plumbing:** enrich the captured
    // blocked-set with `published_at` and `behavioral_tags_hash` per
    // package, drawing from the registry metadata the resolver
    // already fetched (5-min TTL cache). On fresh resolutions this is
    // effectively free; on offline / fast-path paths we pass empty
    // metadata and the fields stay `None` (graceful degradation).
    let blocked_set_metadata = build_blocked_set_metadata(arc_client.as_ref(), &packages).await;
    let blocked_capture = crate::build_state::capture_blocked_set_after_install_with_metadata(
        project_dir,
        &store,
        &installed_with_integrity,
        &policy,
        &blocked_set_metadata,
    )?;

    // Show build hint for packages with lifecycle scripts (Phase 25: two-phase model).
    // Scripts are NEVER executed during install — use `lpm build` instead.
    // **Phase 32 Phase 4 M3:** the hint is now gated on the blocked-set
    // fingerprint changing — repeated installs of the same blocked set are silent.
    if !json_output && blocked_capture.should_emit_warning {
        if blocked_capture.all_clear_banner {
            output::success(
                "All previously-blocked packages have been approved. Run `lpm build` to execute their scripts.",
            );
        } else {
            // Phase 46 P1: include integrity so the hint's strict gate
            // matches what `build::run` will do. Previously we passed
            // only (name, version) and the lenient name-only gate
            // could show drifted rich bindings as trusted ✓.
            let all_pkgs: Vec<(String, String, Option<String>)> = packages
                .iter()
                .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
                .collect();
            crate::commands::build::show_install_build_hint(
                &store,
                &all_pkgs,
                &policy,
                project_dir,
            );
            output::info("Run `lpm approve-builds` to review and approve their lifecycle scripts.");
        }
    }

    // Step 7: LPM-Native Intelligence (Phase 5)
    // Read strictness from package.json "lpm" config
    let strict_deps = pkg
        .lpm
        .as_ref()
        .and_then(|l| l.strict_deps.as_deref())
        .unwrap_or("warn");

    if strict_deps != "loose" && !json_output {
        let installed_names: std::collections::HashSet<String> =
            packages.iter().map(|p| p.name.clone()).collect();

        // Phantom dependency detection
        let phantom_result =
            crate::intelligence::detect_phantom_deps(project_dir, &deps, &installed_names);

        if !phantom_result.phantom_imports.is_empty() {
            let icon = if strict_deps == "strict" {
                "✖"
            } else {
                "⚠"
            };
            println!();
            output::warn(&format!(
                "{}  {} phantom dependency import(s) detected:",
                icon,
                phantom_result.phantom_imports.len()
            ));
            for phantom in phantom_result.phantom_imports.iter().take(5) {
                let rel_file = phantom
                    .file
                    .strip_prefix(project_dir)
                    .unwrap_or(&phantom.file);
                println!(
                    "    {} ({}:{})",
                    phantom.package_name.bold(),
                    rel_file.display().to_string().dimmed(),
                    phantom.line,
                );
                if let Some(via) = &phantom.available_via {
                    println!("      {}", via.dimmed());
                }
                println!(
                    "      Fix: {}",
                    format!("lpm install {}", phantom.package_name).dimmed()
                );
            }
            if phantom_result.phantom_imports.len() > 5 {
                println!(
                    "    ... and {} more",
                    phantom_result.phantom_imports.len() - 5
                );
            }
        }

        // Import verification (only in strict mode)
        if strict_deps == "strict" {
            let verification =
                crate::intelligence::verify_imports(project_dir, &installed_names, &deps);
            if !verification.unresolved.is_empty() {
                println!();
                output::warn(&format!(
                    "✖  {} import(s) will fail at runtime:",
                    verification.unresolved.len()
                ));
                for unresolved in &verification.unresolved {
                    let rel_file = unresolved
                        .file
                        .strip_prefix(project_dir)
                        .unwrap_or(&unresolved.file);
                    println!(
                        "    {}:{} → {}",
                        rel_file.display().to_string().dimmed(),
                        unresolved.line,
                        format!("import \"{}\"", unresolved.specifier).bold(),
                    );
                    println!("      {}", unresolved.suggestion.dimmed());
                }
            }
        }

        // Quality warnings for LPM packages
        let lpm_packages: Vec<(String, String)> = packages
            .iter()
            .filter(|p| p.is_lpm)
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();

        if !lpm_packages.is_empty() {
            let quality_threshold = pkg
                .lpm
                .as_ref()
                .and_then(|l| l.strict_deps.as_deref()) // reuse as quality gate
                .map(|_| 50u32) // warn if below 50 when any strictness is set
                .unwrap_or(30); // default: only warn below 30

            // Phase 35 Step 6 fix (empty-bearer regression #1).
            // Pre-fix this site constructed a fresh RegistryClient and
            // attached `crate::auth::get_token(...).unwrap_or_default()`,
            // which sent literal `Authorization: Bearer ` (empty value)
            // headers when no token was stored. Now we use the
            // injected client directly — its `current_bearer` filters
            // empty strings and its `SessionManager` carries the
            // refresh-eligible session.
            let warnings = crate::intelligence::check_install_quality(
                client,
                &lpm_packages,
                quality_threshold,
            )
            .await;

            for warning in &warnings {
                let icon = match warning.severity {
                    crate::intelligence::WarningSeverity::Critical => "✖".to_string(),
                    crate::intelligence::WarningSeverity::Warning => "⚠".to_string(),
                    crate::intelligence::WarningSeverity::Info => "ℹ".to_string(),
                };
                println!(
                    "  {icon} {}@{}: {}",
                    warning.package_name, warning.version, warning.message
                );
            }

            // Security summary for ALL packages (client-side analysis + registry enrichment)
            if !no_security_summary {
                let all_packages: Vec<(String, String, bool)> = packages
                    .iter()
                    .map(|p| (p.name.clone(), p.version.clone(), p.is_lpm))
                    .collect();
                // Phase 35 Step 6 fix (empty-bearer regression #2).
                // Same defect as the intelligence::check_install_quality
                // site above; resolved the same way — use the injected
                // client.
                crate::security_check::post_install_security_summary(
                    client,
                    &store,
                    &all_packages,
                    json_output,
                    false, // not quiet — show Medium tier too
                )
                .await;
            }
        }
    }

    // Step 8: Auto-install skills for direct LPM packages
    if !json_output && !no_skills {
        let lpm_packages: Vec<String> = packages
            .iter()
            .filter(|p| p.is_lpm && p.is_direct)
            .map(|p| p.name.clone())
            .collect();

        if !lpm_packages.is_empty() {
            install_skills_for_packages(&arc_client, &lpm_packages, project_dir, no_editor_setup)
                .await;
        }
    }

    // Step 9: Write lockfile (only if we resolved fresh)
    if !used_lockfile {
        let mut lockfile = lpm_lockfile::Lockfile::new();
        for p in &packages {
            let dep_strings: Vec<String> = p
                .dependencies
                .iter()
                .map(|(dep_name, dep_ver)| format!("{dep_name}@{dep_ver}"))
                .collect();

            // Phase 40 P2 — persist npm-alias edges as `[local, target]`
            // pairs. The matching `<local>@<version>` entry is already
            // in `dep_strings`; this map keys the alias target so the
            // warm-install path can rebuild `InstallPackage.aliases`
            // without re-running the resolver.
            let alias_pairs: Vec<[String; 2]> = p
                .aliases
                .iter()
                .map(|(local, target)| [local.clone(), target.clone()])
                .collect();

            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                source: Some(p.source.clone()),
                integrity: p.integrity.clone(),
                dependencies: dep_strings,
                alias_dependencies: alias_pairs,
                // Phase 43 — persist the tarball URL the registry
                // returned at resolve time so warm installs can skip
                // the per-package metadata round-trip. Consumed by
                // `try_lockfile_fast_path` through `evaluate_cached_url`.
                tarball: p.tarball_url.clone(),
            });
        }

        // Phase 40 P2 — persist the root-level alias map so warm
        // installs can rebuild `node_modules/<local>/` symlinks
        // without re-resolving. The HashMap → BTreeMap conversion
        // gives deterministic serialized order, matching the
        // sort-by-name policy on `packages`.
        lockfile.root_aliases = root_aliases_for_lockfile(&packages, &deps);

        lockfile
            .write_all(&lockfile_path)
            .map_err(|e| LpmError::Registry(format!("failed to write lockfile: {e}")))?;

        lpm_lockfile::ensure_gitattributes(project_dir)
            .map_err(|e| LpmError::Registry(format!("failed to ensure .gitattributes: {e}")))?;

        if !json_output {
            let lockb_path = lockfile_path.with_extension("lockb");
            let lockb_size = std::fs::metadata(&lockb_path).map(|m| m.len()).unwrap_or(0);
            output::info(&format!(
                "Lockfile  lpm.lock ({} packages) + lpm.lockb ({})",
                lockfile.packages.len(),
                lpm_common::format_bytes(lockb_size),
            ));
        }
    } else if let Some(mut lockfile) = fast_path_lockfile.take() {
        // Phase 43 generalized writeback (P43-2 Change 3). When the
        // fast path ran, we skip the fresh-resolve writer above. But
        // two signals can still require a rewrite:
        //
        //   1. `fresh_urls` is non-empty — at least one URL diverged
        //      from the stored value (stale-URL recovery and/or
        //      origin-mismatch rebase). Without the rewrite, the
        //      divergence recurs on every subsequent install.
        //   2. `needs_binary_upgrade` — the v2 `lpm.lockb` was
        //      missing or out-of-version. Fast-path-only runs would
        //      otherwise defer the v1→v2 binary migration
        //      indefinitely; force it here so read-only commands
        //      (`lpm outdated`, `lpm upgrade`) immediately benefit.
        //
        // On the true happy path (URLs all match, binary current),
        // both signals are clean and no write fires — lockfiles stay
        // byte-identical, CI diffs stay empty.
        let url_churn = !fresh_urls.is_empty();
        if url_churn || needs_binary_upgrade {
            // Patch `lp.tarball` in place for every package whose
            // final URL diverged. Linear scan over `fresh_urls` is
            // fine — even large workspaces have <1k packages and
            // churn is rare in steady state.
            for lp in &mut lockfile.packages {
                if let Some(url) = fresh_urls.get(&(lp.name.clone(), lp.version.clone())) {
                    lp.tarball = Some(url.clone());
                }
            }

            lockfile
                .write_all(&lockfile_path)
                .map_err(|e| LpmError::Registry(format!("failed to rewrite lockfile: {e}")))?;

            if !json_output {
                // Observable output so the user can see why the
                // lockfile's mtime changed.
                if url_churn && needs_binary_upgrade {
                    output::info(&format!(
                        "Refreshed {} stale tarball URL(s) + upgraded lpm.lockb to v{}",
                        fresh_urls.len(),
                        lpm_lockfile::binary::BINARY_VERSION,
                    ));
                } else if url_churn {
                    output::info(&format!(
                        "Refreshed {} stale tarball URL(s) in lockfile",
                        fresh_urls.len(),
                    ));
                } else {
                    output::info(&format!(
                        "Upgraded lpm.lockb to v{} format",
                        lpm_lockfile::binary::BINARY_VERSION,
                    ));
                }
            }
        }
    }

    // Step 10: Auto-build trusted packages (after lockfile is written)
    // Triggers when: --auto-build flag, lpm.scripts.autoBuild config, or ALL scripted packages are trusted
    //
    // Phase 46 P1: consolidated into ScriptPolicyConfig so all four
    // script-related keys come from a single read.
    let config_auto_build =
        crate::script_policy_config::ScriptPolicyConfig::from_package_json(project_dir).auto_build;
    // Phase 46 P1: include integrity so the auto-build predicate's
    // strict gate matches what `build::run` will do. A drifted rich
    // binding previously satisfied this predicate via the lenient
    // name-only gate and triggered auto-build for a package
    // `build::run` then skipped.
    let all_pkgs_for_build: Vec<(String, String, Option<String>)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
        .collect();
    let all_trusted = crate::commands::build::all_scripted_packages_trusted(
        &store,
        &all_pkgs_for_build,
        &policy,
        project_dir,
    );

    if should_auto_build(auto_build, config_auto_build, all_trusted)
        && let Err(e) = crate::commands::build::run(
            project_dir,
            &[],   // no specific packages — build all trusted
            false, // not --all
            false, // not dry-run
            false, // not --rebuild
            None,  // default timeout
            json_output,
            false, // not --unsafe-full-env
            false, // not --deny-all
        )
        .await
        && !json_output
    {
        output::warn(&format!("Auto-build failed: {e}"));
    }

    let elapsed = start.elapsed();

    // **Phase 32 Phase 5** — persist `.lpm/overrides-state.json`. Three
    // cases:
    // 1. Override set is non-empty → write the fresh state (or, on the
    //    lockfile fast path, preserve the previously-recorded apply
    //    trace so `lpm graph --why` doesn't go blind).
    // 2. Override set is empty AND a stale state file exists → delete
    //    it so introspection commands don't pick up old data.
    // 3. Override set is empty AND no state file → no-op.
    if !override_set.is_empty() {
        let state = if used_lockfile {
            // Lockfile fast path: nothing was re-resolved, so preserve
            // whatever the previous fresh-resolve recorded.
            let prior_applied = prior_overrides_state
                .as_ref()
                .map(|s| s.applied.clone())
                .unwrap_or_default();
            overrides_state::OverridesState::capture_preserving_applied(
                &override_set,
                prior_applied,
            )
        } else {
            overrides_state::OverridesState::capture(&override_set, applied_overrides.clone())
        };
        if let Err(e) = overrides_state::write_state(project_dir, &state) {
            tracing::warn!("failed to write overrides-state.json: {e}");
        }
    } else if prior_overrides_state.is_some()
        && let Err(e) = overrides_state::delete_state(project_dir)
    {
        tracing::warn!("failed to delete stale overrides-state.json: {e}");
    }

    // **Phase 32 Phase 6** — persist `.lpm/patch-state.json`.
    // Audit fix (2026-04-12): preserve the prior `applied` trace on
    // idempotent reruns so `lpm graph --why` doesn't lose provenance
    // when an install does no work. See `persist_patch_state`.
    persist_patch_state(
        project_dir,
        &current_patches,
        &prior_patch_state,
        &applied_patches,
    );

    if json_output {
        let pkg_list: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "source": p.source,
                    "direct": p.is_direct,
                })
            })
            .collect();

        let mut json = serde_json::json!({
            "success": true,
            "packages": pkg_list,
            "count": packages.len(),
            "downloaded": downloaded,
            "cached": cached,
            "linked": link_result.linked,
            "symlinked": link_result.symlinked,
            "used_lockfile": used_lockfile,
            "duration_ms": elapsed.as_millis() as u64,
            "timing": {
                "resolve_ms": resolve_ms,
                "fetch_ms": fetch_ms,
                "link_ms": link_ms,
                "total_ms": elapsed.as_millis(),
                // Phase 40 P1/P3a: nested resolver breakdown.
                //
                // P1 seeded this object with `platform_skipped`.
                // P3a grows it with the cold-resolve substage
                // breakdown so consumers can attribute `resolve_ms`
                // to a specific contributor before work starts on
                // P3b (deeper worker walk) / P3c (parallel follow-
                // ups) / P3d (slim batch response).
                //
                // Field shape:
                //   platform_skipped   — optional deps filtered by os/cpu (P1)
                //   initial_batch_ms   — wall-clock for the pre-resolve
                //                        batch prefetch. On warm cache or
                //                        lockfile-fast-path, zero.
                //   followup_rpc_ms    — metadata RPCs fired by the
                //                        resolver's PubGrub callbacks
                //                        (the P3b/P3c lever).
                //   followup_rpc_count — count of those follow-up RPCs.
                //   parse_ndjson_ms    — serde_json CPU time for
                //                        follow-up batches (P3d lever).
                //   pubgrub_ms         — wall-clock inside
                //                        `pubgrub::resolve()` (includes
                //                        provider callbacks).
                //
                // `resolve_ms` stays as a top-level scalar for
                // backwards compatibility; the substages inside
                // `resolve` are additive observability.
                "resolve": {
                    "platform_skipped": platform_skipped,
                    "initial_batch_ms": initial_batch_ms,
                    "followup_rpc_ms": resolver_stage_timing.followup_rpc_ms,
                    "followup_rpc_count": resolver_stage_timing.followup_rpc_count,
                    "parse_ndjson_ms": resolver_stage_timing.parse_ndjson_ms,
                    "pubgrub_ms": resolver_stage_timing.pubgrub_ms,
                },
                // Phase 38 P0: sub-stage breakdown of the fetch pool. Zeroed
                // when everything is already in the store (lockfile fast path
                // with warm cache). Field shape is the `FetchBreakdown` JSON
                // contract documented on that struct.
                "fetch_breakdown": fetch_breakdown.to_json(),
                // Phase 43 — lockfile-cached URL gate telemetry. All
                // counters zero when every stored URL passed (common
                // case in steady state). `origin_mismatch > 0` is
                // expected after `LPM_REGISTRY_URL` switches;
                // `shape_mismatch > 0` is a BUG signal — the writer
                // should never emit a gate-rejectable URL.
                "tarball_url_gate": gate_stats.to_json(),
                // Phase 38 P3: speculative-fetch stats. All fields zero
                // when `LPM_SPEC_FETCH=0` disables the dispatcher OR when
                // every root is already in the store before the metadata
                // RPC starts. Documented on `SpeculativeStats`.
                "speculative": spec_stats.to_json(),
            },
            "warnings": [],
            "errors": [],
        });
        // Phase 32 Phase 2: surface workspace target set for agents.
        // None for legacy/standalone callers; Some(...) for the filtered path.
        if let Some(targets) = target_set {
            json["target_set"] =
                serde_json::Value::Array(targets.iter().map(|s| serde_json::json!(s)).collect());
        }
        // Phase 32 Phase 2 audit fix #3: surface workspace member deps that
        // were linked locally instead of going through the registry.
        if !workspace_member_deps.is_empty() {
            json["workspace_members"] = serde_json::Value::Array(
                workspace_member_deps
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "name": m.name,
                            "version": m.version,
                            "source_dir": m.source_dir.display().to_string(),
                        })
                    })
                    .collect(),
            );
        }
        // **Phase 32 Phase 5:** surface the override apply trace. Empty
        // when no overrides were declared OR when the lockfile fast
        // path was taken (in which case the persisted state file holds
        // the most recent trace from a fresh resolve).
        if !applied_overrides.is_empty() {
            json["applied_overrides"] = serde_json::Value::Array(
                applied_overrides
                    .iter()
                    .map(|h| {
                        serde_json::json!({
                            "raw_key": h.raw_key,
                            "source": h.source,
                            "package": h.package,
                            "from_version": h.from_version,
                            "to_version": h.to_version,
                            "via_parent": h.via_parent,
                        })
                    })
                    .collect(),
            );
        }
        json["overrides_count"] = serde_json::json!(override_set.len());
        json["overrides_fingerprint"] = serde_json::json!(override_set.fingerprint());

        // **Phase 32 Phase 6** — surface the patch apply trace + counts.
        // Audit fix (2026-04-12): filter to entries that ACTUALLY did
        // work this run via `touched_anything()`. A no-op idempotent
        // rerun where every file already had the expected post-patch
        // bytes will report an empty `applied_patches` array — that's
        // the correct per-run signal. The patches are still in effect
        // (the state file still records them), but we did no work, so
        // we don't claim we did. Always emitted so agents can rely on
        // the field's existence.
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|a| a.touched_anything())
            .collect();
        json["applied_patches"] = applied_patches_to_json(&applied_patches_summary, project_dir);
        json["patches_count"] = serde_json::json!(current_patches.len());
        json["patches_fingerprint"] = serde_json::json!(current_patch_fingerprint);

        // **Phase 32 Phase 4 M3:** surface the install-time blocked set so
        // agents and CI can drive `lpm approve-builds` without re-scanning.
        json["blocked_count"] = serde_json::json!(blocked_capture.state.blocked_packages.len());
        json["blocked_set_changed"] = serde_json::json!(blocked_capture.should_emit_warning);
        json["blocked_set_fingerprint"] =
            serde_json::json!(blocked_capture.state.blocked_set_fingerprint);
        json["blocked_packages"] = serde_json::Value::Array(
            blocked_capture
                .state
                .blocked_packages
                .iter()
                .map(|bp| {
                    serde_json::json!({
                        "name": bp.name,
                        "version": bp.version,
                        "integrity": bp.integrity,
                        "script_hash": bp.script_hash,
                        "phases_present": bp.phases_present,
                        "binding_drift": bp.binding_drift,
                    })
                })
                .collect(),
        );
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        // **Phase 32 Phase 5** — print the override apply summary BEFORE
        // the success line so it doesn't get lost at the bottom of the
        // output. Only emit on the fresh-resolution path; the lockfile
        // fast path already had the summary printed during the
        // resolution that produced the lockfile, so re-emitting it
        // would be misleading ("Applied N overrides" implies we just
        // applied them).
        if !applied_overrides.is_empty() {
            println!();
            output::info(&format!(
                "Applied {} override{}:",
                applied_overrides.len().to_string().bold(),
                if applied_overrides.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ));
            for hit in &applied_overrides {
                let source_ref = hit.source_display();
                let parent_suffix = match &hit.via_parent {
                    Some(p) => format!(", reached through {}", p.bold()),
                    None => String::new(),
                };
                println!(
                    "   {} {} → {} (via {}{})",
                    hit.package.bold(),
                    hit.from_version.dimmed(),
                    hit.to_version.bold(),
                    source_ref,
                    parent_suffix,
                );
            }
        }

        // **Phase 32 Phase 6** — summary of applied patches. Mirrors
        // the override summary above. **Audit fix (2026-04-12):** filter
        // to entries that ACTUALLY did work this run (`touched_anything`)
        // so a no-op idempotent rerun doesn't print "Applied 1 patch"
        // with zero files. The patches are still in effect on disk
        // (the state file still records them), but if we did no work
        // we don't claim we did.
        let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
            .iter()
            .filter(|a| a.touched_anything())
            .collect();
        if !applied_patches_summary.is_empty() {
            println!();
            output::info(&format!(
                "Applied {} patch{}:",
                applied_patches_summary.len().to_string().bold(),
                if applied_patches_summary.len() == 1 {
                    ""
                } else {
                    "es"
                }
            ));
            for a in &applied_patches_summary {
                let rel_patch = a
                    .patch_path
                    .strip_prefix(project_dir)
                    .unwrap_or(&a.patch_path);
                let total = a.files_modified + a.files_added + a.files_deleted;
                println!(
                    "   {}@{} ({}, {} file{})",
                    a.name.bold(),
                    a.version.dimmed(),
                    rel_patch.display(),
                    total,
                    if total == 1 { "" } else { "s" },
                );
            }
        }

        println!();
        output::success(&format!(
            "{} packages installed in {:.1}s",
            packages.len().to_string().bold(),
            elapsed.as_secs_f64()
        ));
        println!(
            "  {} linked, {} symlinked",
            link_result.linked.to_string().dimmed(),
            link_result.symlinked.to_string().dimmed(),
        );
        println!(
            "  resolve: {}ms  fetch: {}ms  link: {}ms",
            resolve_ms.to_string().dimmed(),
            fetch_ms.to_string().dimmed(),
            link_ms.to_string().dimmed(),
        );
        println!();
    }

    // Write install-hash so `lpm dev` knows deps are up to date.
    // Phase 34.1: uses the shared compute_install_hash from install_state.
    // Must re-read because Phase 33 save semantics may have modified both
    // package.json and lpm.lock during install (e.g., replacing "*" with "^4.3.6").
    //
    // Phase 44: delegated to `write_install_hash`, which also captures
    // manifest mtimes into the v2 file format so the next up-to-date
    // check can take the mtime fast path.
    if let (Ok(pkg), Ok(lock)) = (
        std::fs::read_to_string(project_dir.join("package.json")),
        std::fs::read_to_string(project_dir.join("lpm.lock")),
    ) {
        let hash = crate::install_state::compute_install_hash(&pkg, &lock);
        let _ = crate::install_state::write_install_hash(project_dir, &hash);
    }

    // Phase 33 audit Finding 1 fix: surface the direct-dep version map
    // for callers (`run_add_packages`, `run_install_filtered_add`) that
    // need to finalize a placeholder-staged manifest entry. The map
    // contains ONLY entries where `is_direct == true`, so transitive
    // collisions on the same name are impossible by construction.
    if let Some(out) = direct_versions_out {
        out.extend(collect_direct_versions(&packages));
    }

    Ok(())
}

fn should_auto_build(auto_build_flag: bool, config_auto_build: bool, all_trusted: bool) -> bool {
    auto_build_flag || config_auto_build || all_trusted
}

/// **Phase 46 P1 metadata plumbing** — build the metadata map that
/// enriches [`crate::build_state::BlockedPackage`] entries with
/// `published_at` (RFC 3339) and `behavioral_tags_hash` (SHA-256 over
/// the sorted set of active behavioral tags).
///
/// Fetches registry metadata via the existing client API which is
/// backed by a 5-min TTL cache. On fresh resolutions the resolver
/// already populated that cache, so this is a memory-local lookup.
/// On offline installs or registry-unreachable installs, fetches
/// return `Err`; we silently drop those packages from the map and
/// the captured fields stay `None` — documented graceful
/// degradation (see [`crate::build_state::BlockedSetMetadata`]).
///
/// Never returns an error: metadata enrichment is best-effort and
/// must not fail an otherwise-successful install. Any fetch error
/// is recorded as "no entry for this package" and the install
/// proceeds.
async fn build_blocked_set_metadata(
    client: &lpm_registry::RegistryClient,
    packages: &[InstallPackage],
) -> crate::build_state::BlockedSetMetadata {
    let mut out = crate::build_state::BlockedSetMetadata::default();

    for p in packages {
        // Grab the full PackageMetadata so we can read BOTH the top-
        // level `time[version]` (for `published_at`) AND the
        // `versions[version]._behavioralTags` substructure in one
        // fetch. Errors are swallowed per the graceful-degradation
        // contract above.
        let meta = if p.is_lpm {
            match lpm_common::PackageName::parse(&p.name) {
                Ok(pkg_name) => client.get_package_metadata(&pkg_name).await.ok(),
                Err(_) => None,
            }
        } else {
            client.get_npm_package_metadata(&p.name).await.ok()
        };

        let Some(meta) = meta else { continue };

        let published_at = meta.time.get(&p.version).cloned();

        // Extract behavioral tags if present and hash them into the
        // canonical form. `active_tag_names` returns sorted canonical
        // names; `hash_behavioral_tag_set` hashes them deterministically.
        let behavioral_tags_hash = meta
            .versions
            .get(&p.version)
            .and_then(|v| v.behavioral_tags.as_ref())
            .map(|tags| {
                let names = tags.active_tag_names();
                lpm_security::triage::hash_behavioral_tag_set(&names)
            });

        // Only insert if at least ONE field is populated — empty
        // entries just waste map memory. Callers get `None` for
        // absent keys either way.
        if published_at.is_some() || behavioral_tags_hash.is_some() {
            out.insert(
                p.name.clone(),
                p.version.clone(),
                crate::build_state::BlockedSetMetadataEntry {
                    published_at,
                    behavioral_tags_hash,
                },
            );
        }
    }

    out
}

// Phase 34.1: is_install_up_to_date() moved to crate::install_state::check_install_state()

/// Try to use the lockfile as a fast path.
///
/// Returns `Some(LockfileFastPath { packages, lockfile,
/// needs_binary_upgrade })` if the lockfile exists AND every declared
/// dependency in package.json has a matching entry in the lockfile.
/// Otherwise returns `None` to signal that fresh resolution is needed.
///
/// The parsed `Lockfile` is returned alongside the install packages so
/// the install driver can patch `LockedPackage.tarball` and re-emit
/// the lockfile on the generalized-writeback path (Phase 43 P43-2
/// Change 3) without re-parsing. The `needs_binary_upgrade` flag
/// tells the driver whether a rewrite is needed even when no URL
/// diverged (e.g., pre-Phase-43 v1 `lpm.lockb` on disk, or missing
/// entirely — migration completes on first fast-path install
/// instead of being deferred to the next fresh resolve).
/// Return type for [`try_lockfile_fast_path`]. Carries the parsed
/// lockfile back to the install driver (so it can be patched + re-
/// written on the generalized-writeback path) alongside the install
/// packages derived from it, plus a `needs_binary_upgrade` flag
/// indicating that the binary lockfile is missing or out-of-version
/// and should be re-emitted at install-end (the fast-path install
/// itself doesn't normally write the lockfile).
struct LockfileFastPath {
    packages: Vec<InstallPackage>,
    /// Parsed lockfile. Owned by the caller so
    /// `LockedPackage.tarball` fields can be patched with post-fetch
    /// URLs before `write_all` is called on the writeback path.
    lockfile: lpm_lockfile::Lockfile,
    /// True when the v2 `lpm.lockb` was missing or opened with
    /// `UnsupportedVersion`. Triggers a writeback even when no URL
    /// diverged — otherwise the migration from a v1 binary (or no
    /// binary at all) would never complete on fast-path-only runs.
    needs_binary_upgrade: bool,
}

fn try_lockfile_fast_path(
    lockfile_path: &Path,
    deps: &HashMap<String, String>,
    // Phase 43 — the URL-reuse gate needs the client to check
    // origin (`is_configured_origin`) and the shared `GateStats`
    // to bump mismatch counters. Both passed by ref; the fast
    // path runs synchronously so no Arc is needed here.
    client: &RegistryClient,
    gate_stats: &GateStats,
) -> Option<LockfileFastPath> {
    if !lpm_lockfile::Lockfile::exists(lockfile_path) {
        return None;
    }

    // Phase 43 — probe the binary lockfile state so the driver can
    // decide whether to trigger a writeback for migration purposes
    // even when no URL diverged. `lpm.lockb` missing OR opened with
    // `UnsupportedVersion` → needs rewrite. Other errors (structural
    // corruption) leave the file alone so users can forensically
    // inspect; `read_fast` will still fall back to TOML below.
    let binary_path = lockfile_path.with_extension("lockb");
    let needs_binary_upgrade = match lpm_lockfile::BinaryLockfileReader::open(&binary_path) {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(lpm_lockfile::LockfileError::UnsupportedVersion { .. }) => true,
        Err(_) => false,
    };

    let lockfile = lpm_lockfile::Lockfile::read_fast(lockfile_path).ok()?;

    // Validate all package sources are safe (HTTPS registries or localhost)
    for lp in &lockfile.packages {
        if let Some(ref source) = lp.source
            && !lpm_lockfile::is_safe_source(source)
        {
            tracing::warn!(
                "package {}@{} has unsafe source URL: {} — skipping lockfile fast path",
                lp.name,
                lp.version,
                source
            );
            return None; // Force re-resolution from trusted registries
        }
    }

    // Phase 40 P2 — verify every declared root dep has a lockfile
    // entry. For aliased roots, check the ALIAS TARGET (looked up via
    // `lockfile.root_aliases`) rather than the alias key, since the
    // lockfile is keyed by canonical registry names.
    for local in deps.keys() {
        let target = lockfile
            .root_aliases
            .get(local)
            .map(String::as_str)
            .unwrap_or(local.as_str());
        if lockfile.find_package(target).is_none() {
            tracing::debug!(
                "lockfile miss: {local} (resolved target {target}) not found, re-resolving"
            );
            return None;
        }
    }

    // Build the direct-target-name set: root deps (via alias redirect)
    // → their canonical names. Matches the fresh-resolve logic in
    // `resolved_to_install_packages`.
    let direct_target_names: std::collections::HashSet<String> = deps
        .keys()
        .map(|local| {
            lockfile
                .root_aliases
                .get(local)
                .cloned()
                .unwrap_or_else(|| local.clone())
        })
        .collect();

    // Rebuild per-package root_link_names from root_aliases + deps,
    // using the same algorithm as `resolved_to_install_packages` so
    // the warm-install layout matches the fresh-install layout
    // byte-for-byte.
    let mut root_link_map: HashMap<(String, String), Vec<String>> = HashMap::new();
    for local in deps.keys() {
        let target = lockfile
            .root_aliases
            .get(local)
            .cloned()
            .unwrap_or_else(|| local.clone());
        if let Some(lp) = lockfile.find_package(&target) {
            root_link_map
                .entry((target, lp.version.clone()))
                .or_default()
                .push(local.clone());
        }
    }
    for locals in root_link_map.values_mut() {
        locals.sort();
    }

    // Convert locked packages to InstallPackage
    let packages: Vec<InstallPackage> = lockfile
        .packages
        .iter()
        .map(|lp| {
            let is_lpm = lp.name.starts_with("@lpm.dev/");

            // Parse dependency strings back to (name, version) tuples
            let dependencies: Vec<(String, String)> = lp
                .dependencies
                .iter()
                .filter_map(|dep_str| {
                    // Format: "name@version"
                    dep_str
                        .rfind('@')
                        .map(|at| (dep_str[..at].to_string(), dep_str[at + 1..].to_string()))
                })
                .collect();

            // Phase 40 P2 — restore per-package alias map from the
            // lockfile's `alias-dependencies` entries.
            let aliases: HashMap<String, String> = lp
                .alias_dependencies
                .iter()
                .map(|pair| (pair[0].clone(), pair[1].clone()))
                .collect();

            let root_link_names = root_link_map
                .get(&(lp.name.clone(), lp.version.clone()))
                .cloned();

            InstallPackage {
                name: lp.name.clone(),
                version: lp.version.clone(),
                source: lp
                    .source
                    .clone()
                    .unwrap_or_else(|| "registry+https://registry.npmjs.org".to_string()),
                dependencies,
                aliases,
                // `root_link_names` restored from the lockfile's
                // `root-aliases` map. `None` for transitive packages
                // (no root symlink); `Some(vec)` for direct deps,
                // including aliased ones.
                root_link_names,
                is_direct: direct_target_names.contains(&lp.name),
                is_lpm,
                integrity: lp.integrity.clone(),
                // Phase 43 — gate a stored URL against scheme/shape/
                // origin before reusing it. Any rejection downgrades
                // to `None`, which forces on-demand lookup against
                // the current registry.
                tarball_url: lp.tarball.as_deref().and_then(|url| {
                    match evaluate_cached_url(url, client) {
                        GateDecision::Accepted => Some(url.to_string()),
                        GateDecision::RejectedScheme => {
                            // Writer never emits scheme-unsafe URLs,
                            // so this path signals a corrupt lockfile.
                            // Counter-bumped for telemetry symmetry
                            // with shape/origin — makes corrupt-
                            // lockfile signals observable instead of
                            // trace-log-only.
                            gate_stats
                                .scheme_mismatch
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::warn!(
                                "cached tarball URL for {}@{} has unsafe scheme; \
                                 falling back to on-demand lookup",
                                lp.name,
                                lp.version,
                            );
                            None
                        }
                        GateDecision::RejectedShape => {
                            gate_stats
                                .shape_mismatch
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            tracing::warn!(
                                "cached tarball URL for {}@{} failed shape check; \
                                 falling back to on-demand lookup",
                                lp.name,
                                lp.version,
                            );
                            None
                        }
                        GateDecision::RejectedOrigin => {
                            // Expected after `LPM_REGISTRY_URL` switch:
                            // stored `@lpm.dev/*` URLs mismatch the new
                            // origin and fall through to on-demand
                            // lookup against the mirror. The writeback
                            // trigger (P43-2 Change 3) will persist the
                            // rebased URLs on the next install.
                            gate_stats
                                .origin_mismatch
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            None
                        }
                    }
                }),
            }
        })
        .collect();

    Some(LockfileFastPath {
        packages,
        lockfile,
        needs_binary_upgrade,
    })
}

/// Phase 40 P2 — rebuild the root-level alias map from `packages`
/// for lockfile persistence. Walks each package's `root_link_names`;
/// any local name that differs from the package's canonical name is
/// an alias declaration (e.g., `strip-ansi-cjs` on a `strip-ansi`
/// InstallPackage). Returns a `BTreeMap` so serialized TOML has
/// deterministic order across runs.
fn root_aliases_for_lockfile(
    packages: &[InstallPackage],
    _deps: &HashMap<String, String>,
) -> std::collections::BTreeMap<String, String> {
    let mut aliases = std::collections::BTreeMap::new();
    for pkg in packages {
        if let Some(link_names) = &pkg.root_link_names {
            for local in link_names {
                if local != &pkg.name {
                    aliases.insert(local.clone(), pkg.name.clone());
                }
            }
        }
    }
    aliases
}

/// Convert resolver output to InstallPackage list.
///
/// Phase 40 P2 — the `root_aliases` map (from the resolver's
/// `ResolveResult`) is used to (1) compute `is_direct` for aliased
/// root deps whose canonical name does NOT appear in `deps.keys()`
/// (the pre-P2 `deps.contains_key(&name)` missed these) and (2)
/// copy the per-package transitive alias map from
/// `ResolvedPackage.aliases`. Root-level `root_link_names` are
/// filled in later in the install pipeline, since they require
/// matching resolved versions against the root `deps` map.
fn resolved_to_install_packages(
    resolved: &[ResolvedPackage],
    deps: &HashMap<String, String>,
    root_aliases: &HashMap<String, String>,
) -> Vec<InstallPackage> {
    // Targets the root either declares directly OR reaches via an
    // npm-alias: each such target's (any version's) resolved package
    // is considered a direct dep for scripts/display.
    let direct_target_names: std::collections::HashSet<String> = deps
        .keys()
        .map(|local| {
            root_aliases
                .get(local)
                .cloned()
                .unwrap_or_else(|| local.clone())
        })
        .collect();

    // For each resolved direct package, the list of local names the
    // root declared for it. Keyed by (canonical_name, resolved_version)
    // so the dual-reference case (same version referenced canonically
    // AND by an alias) produces multiple root symlinks. Built by
    // walking the root `deps` once: each declaration `local → range`
    // picks up a single (target, resolved_version) pair via
    // `root_aliases` + the resolved set.
    let resolved_target_versions: HashMap<String, String> = resolved
        .iter()
        .map(|r| (r.package.canonical_name(), r.version.to_string()))
        .collect();
    let mut root_link_map: HashMap<(String, String), Vec<String>> = HashMap::new();
    for local in deps.keys() {
        let target = root_aliases
            .get(local)
            .cloned()
            .unwrap_or_else(|| local.clone());
        if let Some(version) = resolved_target_versions.get(&target) {
            root_link_map
                .entry((target, version.clone()))
                .or_default()
                .push(local.clone());
        }
    }
    // Stable ordering so snapshot tests and binary round-trips don't
    // flap on HashMap iteration order.
    for locals in root_link_map.values_mut() {
        locals.sort();
    }

    // **Phase 41 dedup.** The resolver can emit multiple `ResolvedPackage`
    // rows for the same `(canonical_name, version)` tuple when Phase 40
    // P4 splits a subtree for multi-version peer-dep resolution: each
    // split scope produces its own row differing only in
    // `ResolverPackage::context`. `canonical_name()` strips that context,
    // so every split collapses to the same `InstallPackage`. Without
    // this dedup, downstream stages receive N identical rows for one
    // physical package, which in turn produced N concurrent Phase 3
    // root-symlink creations in `link_finalize` and raced on
    // `std::os::unix::fs::symlink` — leaving whichever thread lost to
    // abort the install with `EEXIST`.
    //
    // First-seen wins. The resolver guarantees that all rows with the
    // same `(canonical_name, version)` agree on everything observable
    // to the install pipeline — same tarball URL, same integrity, same
    // dependency set, same aliases — because they represent the same
    // physical package. Split contexts are a resolver-internal scoping
    // device that doesn't change the store's view of the package.
    //
    // Preserving the resolver's input order keeps lockfile and JSON
    // output deterministic across runs.
    let mut seen: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::with_capacity(resolved.len());
    resolved
        .iter()
        .filter_map(|r| {
            let name = r.package.canonical_name();
            let version = r.version.to_string();
            if !seen.insert((name.clone(), version.clone())) {
                return None;
            }
            let is_lpm = r.package.is_lpm();
            let source = if is_lpm {
                "registry+https://lpm.dev".to_string()
            } else {
                "registry+https://registry.npmjs.org".to_string()
            };
            let root_link_names = root_link_map.get(&(name.clone(), version.clone())).cloned();

            Some(InstallPackage {
                name: name.clone(),
                version,
                source,
                dependencies: r.dependencies.clone(),
                aliases: r.aliases.clone(),
                root_link_names,
                is_direct: direct_target_names.contains(&name),
                is_lpm,
                integrity: r.integrity.clone(),
                tarball_url: r.tarball_url.clone(),
            })
        })
        .collect()
}

/// Offline/shared path: link packages from store, write lockfile, print output.
#[allow(clippy::too_many_arguments)]
async fn run_link_and_finish(
    _client: &RegistryClient,
    project_dir: &Path,
    _deps: &HashMap<String, String>,
    pkg: &lpm_workspace::PackageJson,
    packages: Vec<InstallPackage>,
    downloaded: usize,
    cached: usize,
    used_lockfile: bool,
    json_output: bool,
    start: Instant,
    linker_mode: lpm_linker::LinkerMode,
    force: bool,
    workspace_member_deps: &[WorkspaceMemberLink],
) -> Result<(), LpmError> {
    let store = PackageStore::default_location()?;

    let link_targets: Vec<LinkTarget> = packages
        .iter()
        .map(|p| LinkTarget {
            name: p.name.clone(),
            version: p.version.clone(),
            store_path: store.package_dir(&p.name, &p.version),
            dependencies: p.dependencies.clone(),
            aliases: p.aliases.clone(),
            is_direct: p.is_direct,
            root_link_names: p.root_link_names.clone(),
        })
        .collect();

    let link_start = Instant::now();
    let link_result = match linker_mode {
        lpm_linker::LinkerMode::Hoisted => lpm_linker::link_packages_hoisted(
            project_dir,
            &link_targets,
            force,
            pkg.name.as_deref(),
        )?,
        lpm_linker::LinkerMode::Isolated => {
            lpm_linker::link_packages(project_dir, &link_targets, force, pkg.name.as_deref())?
        }
    };
    let link_ms = link_start.elapsed().as_millis();

    // Phase 32 Phase 2 audit fix #3: link workspace member dependencies AFTER
    // the regular linker run. Same rationale as the online path — see
    // `run_with_options`. Offline mode does not write a lockfile entry for
    // workspace members because they're never resolved through the registry.
    let workspace_links_created = link_workspace_members(project_dir, workspace_member_deps)?;
    if workspace_links_created > 0 && !json_output {
        output::info(&format!(
            "Linked {} workspace member(s)",
            workspace_links_created.to_string().bold()
        ));
    }

    // **Phase 32 Phase 6 — apply patches in offline mode too.**
    // Mirror of the online path. The drift gate already ran in
    // `run_with_options` BEFORE this function was reached, so any
    // declared patch is guaranteed to match the previously-recorded
    // fingerprint at this point. The apply pass enforces store
    // integrity binding per-package and is safe to run offline because
    // the store baseline is local-only and the linker has just
    // materialized everything.
    let current_patches: HashMap<String, PatchedDependencyEntry> = pkg
        .lpm
        .as_ref()
        .map(|l| l.patched_dependencies.clone())
        .unwrap_or_default();
    let applied_patches = apply_patches_for_install(
        &current_patches,
        &link_result,
        &store,
        project_dir,
        json_output,
    )?;

    // Lifecycle script security audit (two-phase model: install never runs scripts).
    // Scripts are NEVER executed during install — use `lpm build` instead.
    // This matches the online install path exactly.
    let policy = lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));

    // **Phase 32 Phase 4 M3:** capture the install-time blocked set into
    // build-state.json. Same wiring as the online path — see comment there.
    let installed_with_integrity: Vec<(String, String, Option<String>)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
        .collect();
    let blocked_capture = crate::build_state::capture_blocked_set_after_install(
        project_dir,
        &store,
        &installed_with_integrity,
        &policy,
    )?;

    if !json_output && blocked_capture.should_emit_warning {
        if blocked_capture.all_clear_banner {
            output::success(
                "All previously-blocked packages have been approved. Run `lpm build` to execute their scripts.",
            );
        } else {
            // Phase 46 P1: include integrity so the hint's strict gate
            // matches what `build::run` will do. Previously we passed
            // only (name, version) and the lenient name-only gate
            // could show drifted rich bindings as trusted ✓.
            let all_pkgs: Vec<(String, String, Option<String>)> = packages
                .iter()
                .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
                .collect();
            crate::commands::build::show_install_build_hint(
                &store,
                &all_pkgs,
                &policy,
                project_dir,
            );
            output::info("Run `lpm approve-builds` to review and approve their lifecycle scripts.");
        }
    }

    // Write lockfile if needed
    if !used_lockfile {
        let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
        let mut lockfile = lpm_lockfile::Lockfile::new();
        for p in &packages {
            let dep_strings: Vec<String> = p
                .dependencies
                .iter()
                .map(|(n, v)| format!("{n}@{v}"))
                .collect();
            let alias_pairs: Vec<[String; 2]> = p
                .aliases
                .iter()
                .map(|(local, target)| [local.clone(), target.clone()])
                .collect();
            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                source: Some(p.source.clone()),
                integrity: p.integrity.clone(),
                dependencies: dep_strings,
                alias_dependencies: alias_pairs,
                // Phase 43 — persist the tarball URL the registry
                // returned at resolve time so warm installs can skip
                // the per-package metadata round-trip. Consumed by
                // `try_lockfile_fast_path` through `evaluate_cached_url`.
                tarball: p.tarball_url.clone(),
            });
        }
        lockfile.root_aliases = root_aliases_for_lockfile(&packages, _deps);
        lockfile
            .write_all(&lockfile_path)
            .map_err(|e| LpmError::Registry(format!("failed to write lockfile: {e}")))?;

        lpm_lockfile::ensure_gitattributes(project_dir)
            .map_err(|e| LpmError::Registry(format!("failed to ensure .gitattributes: {e}")))?;

        if !json_output {
            let lockb_path = lockfile_path.with_extension("lockb");
            let lockb_size = std::fs::metadata(&lockb_path).map(|m| m.len()).unwrap_or(0);
            output::info(&format!(
                "Lockfile  lpm.lock ({} packages) + lpm.lockb ({})",
                lockfile.packages.len(),
                lpm_common::format_bytes(lockb_size),
            ));
        }
    }

    let elapsed = start.elapsed();

    // **Phase 32 Phase 6** — persist patch state in offline mode too.
    // The drift gate already ran in `run_with_options`, so reaching
    // this point means the on-disk state file (if any) matches the
    // current parsed map fingerprint, OR both sides are empty.
    //
    // **Audit fix (2026-04-12):** re-read the prior state here so the
    // persist helper can preserve the prior `applied` trace on
    // idempotent reruns (the alternative — passing it down from
    // `run_with_options` — would require threading the value through
    // the offline early-return). The cost is one extra `read` of a
    // ~few-KB JSON file.
    let prior_patch_state_for_offline = patch_state::read_state(project_dir);
    persist_patch_state(
        project_dir,
        &current_patches,
        &prior_patch_state_for_offline,
        &applied_patches,
    );

    // Compute the filtered summary once; reuse for JSON + human output.
    let applied_patches_summary: Vec<&patch_engine::AppliedPatch> = applied_patches
        .iter()
        .filter(|a| a.touched_anything())
        .collect();

    if json_output {
        let pkg_list: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "source": p.source,
                    "direct": p.is_direct,
                })
            })
            .collect();

        let mut json = serde_json::json!({
            "packages": pkg_list,
            "count": packages.len(),
            "downloaded": downloaded,
            "cached": cached,
            "linked": link_result.linked,
            "symlinked": link_result.symlinked,
            "used_lockfile": used_lockfile,
            "offline": true,
            "duration_ms": elapsed.as_millis() as u64,
            "timing": {
                "link_ms": link_ms,
                "total_ms": elapsed.as_millis(),
            },
            "warnings": [],
            "errors": [],
        });
        // Phase 32 Phase 2 audit fix #3: surface workspace member deps that
        // were linked locally instead of going through the registry.
        if !workspace_member_deps.is_empty() {
            json["workspace_members"] = serde_json::Value::Array(
                workspace_member_deps
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "name": m.name,
                            "version": m.version,
                            "source_dir": m.source_dir.display().to_string(),
                        })
                    })
                    .collect(),
            );
        }
        // **Phase 32 Phase 6** — surface applied_patches in offline mode.
        // Audit fix (2026-04-12): use the filtered summary so a no-op
        // idempotent rerun reports an empty array.
        json["applied_patches"] = applied_patches_to_json(&applied_patches_summary, project_dir);
        json["patches_count"] = serde_json::json!(current_patches.len());
        json["patches_fingerprint"] =
            serde_json::json!(patch_state::compute_fingerprint(&current_patches));
        // **Phase 32 Phase 4 M3:** surface the install-time blocked set so
        // agents and CI can drive `lpm approve-builds` without re-scanning.
        // Mirrors the online path.
        json["blocked_count"] = serde_json::json!(blocked_capture.state.blocked_packages.len());
        json["blocked_set_changed"] = serde_json::json!(blocked_capture.should_emit_warning);
        json["blocked_set_fingerprint"] =
            serde_json::json!(blocked_capture.state.blocked_set_fingerprint);
        json["blocked_packages"] = serde_json::Value::Array(
            blocked_capture
                .state
                .blocked_packages
                .iter()
                .map(|bp| {
                    serde_json::json!({
                        "name": bp.name,
                        "version": bp.version,
                        "integrity": bp.integrity,
                        "script_hash": bp.script_hash,
                        "phases_present": bp.phases_present,
                        "binding_drift": bp.binding_drift,
                    })
                })
                .collect(),
        );
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        // **Phase 32 Phase 6** — patch summary in human mode.
        // Audit fix (2026-04-12): use the filtered summary so a no-op
        // idempotent rerun does NOT print "Applied 1 patch" with zero
        // files.
        if !applied_patches_summary.is_empty() {
            println!();
            output::info(&format!(
                "Applied {} patch{}:",
                applied_patches_summary.len().to_string().bold(),
                if applied_patches_summary.len() == 1 {
                    ""
                } else {
                    "es"
                }
            ));
            for a in &applied_patches_summary {
                let rel_patch = a
                    .patch_path
                    .strip_prefix(project_dir)
                    .unwrap_or(&a.patch_path);
                let total = a.files_modified + a.files_added + a.files_deleted;
                println!(
                    "   {}@{} ({}, {} file{})",
                    a.name.bold(),
                    a.version.dimmed(),
                    rel_patch.display(),
                    total,
                    if total == 1 { "" } else { "s" },
                );
            }
        }
        println!();
        output::success(&format!(
            "{} packages installed in {:.1}s",
            packages.len().to_string().bold(),
            elapsed.as_secs_f64()
        ));
        println!(
            "  {} linked, {} symlinked",
            link_result.linked.to_string().dimmed(),
            link_result.symlinked.to_string().dimmed(),
        );
        println!();
    }

    Ok(())
}

/// Phase 38 P3: pick the highest version in a `PackageMetadata` that
/// satisfies the given npm range string. Returns the concrete
/// `(version, tarball_url, integrity)` tuple so the caller can dispatch
/// a speculative download without waiting for PubGrub.
///
/// This is the lightweight analog of what PubGrub does in the conflict-
/// free case: pick the newest range-satisfying version. Mismatches with
/// PubGrub's final pick (~5% of real-world trees, higher in workspaces
/// with tight peer constraints) produce a wasted tarball in the store
/// — cheap to absorb, GC reclaims later.
///
/// npm dist-tags (e.g. `range = "latest"`) resolve via `dist-tags` first,
/// short-circuiting range parsing. Invalid ranges return `None` and the
/// dispatcher skips the package.
fn pick_speculative_version(
    meta: &lpm_registry::PackageMetadata,
    range_str: &str,
) -> Option<(String, String, Option<String>)> {
    // dist-tag path (e.g. "latest", "next", "beta")
    if let Some(pinned) = meta.dist_tags.get(range_str)
        && let Some(vm) = meta.versions.get(pinned)
        && let Some(url) = vm.tarball_url()
    {
        return Some((
            pinned.clone(),
            url.to_string(),
            vm.integrity().map(|s| s.to_string()),
        ));
    }

    let range = lpm_resolver::NpmRange::parse(range_str).ok()?;
    let mut best: Option<(lpm_resolver::NpmVersion, &str)> = None;
    for (v_str, _vm) in meta.versions.iter() {
        let Ok(v) = lpm_resolver::NpmVersion::parse(v_str) else {
            continue;
        };
        if !range.satisfies(&v) {
            continue;
        }
        let better = best.as_ref().map(|(b, _)| v > *b).unwrap_or(true);
        if better {
            best = Some((v, v_str.as_str()));
        }
    }
    let (_v, v_str) = best?;
    let vm = meta.versions.get(v_str)?;
    let url = vm.tarball_url()?.to_string();
    let integrity = vm.integrity().map(|s| s.to_string());
    Some((v_str.to_string(), url, integrity))
}

/// Phase 38 P3 / Phase 39 P3: stream metadata AND dispatch speculative
/// downloads in parallel with NDJSON arrival. Returns the same complete
/// metadata `HashMap` that `batch_metadata_deep` would — callers are
/// semantically identical to the non-speculative path.
///
/// Dispatched downloads write directly into the real package store, so
/// the post-resolve real-fetch loop sees them as plain
/// `store.has_package()` hits. Mismatches (resolver picks a different
/// version than our naive range-match) cost one wasted tarball each;
/// the wrong version sits in the store until GC reclaims it.
///
/// **Phase 39 P3 scope:** transitive speculation. Roots seed a
/// work queue; as each package's manifest arrives, its chosen version's
/// dependencies are expanded onto the queue (capped at
/// [`SPECULATION_MAX_DEPTH`]). Conflict-free trees (95%+ of real-world
/// shape per npm data) see every downloaded package match what PubGrub
/// ultimately picks. Pathological cases that mismatch still converge
/// correctly via the real fetch loop.
/// RAII-ish join handle returned by [`run_deep_batch_with_speculation`].
/// The caller awaits `join` AFTER running resolver CPU; tarball
/// downloads continue running on the tokio runtime in the meantime.
struct SpeculativeJoin {
    handle: tokio::task::JoinHandle<()>,
    started_at: std::time::Instant,
    dispatched: Arc<std::sync::atomic::AtomicU64>,
    completed: Arc<std::sync::atomic::AtomicU64>,
    task_ms_sum: Arc<std::sync::atomic::AtomicU64>,
    transitive_dispatched: Arc<std::sync::atomic::AtomicU64>,
    max_depth_reached: Arc<std::sync::atomic::AtomicU64>,
    no_version_match: Arc<std::sync::atomic::AtomicU64>,
    unresolved_parked: Arc<std::sync::atomic::AtomicU64>,
}

impl SpeculativeJoin {
    /// Await dispatched speculations and fold final counts into `stats`.
    async fn drain(self, stats: &mut SpeculativeStats) {
        use std::sync::atomic::Ordering::Relaxed;
        let _ = self.handle.await;
        stats.streaming_batch_ms = self.started_at.elapsed().as_millis();
        stats.dispatched = self.dispatched.load(Relaxed);
        stats.completed = self.completed.load(Relaxed);
        stats.task_ms_sum = self.task_ms_sum.load(Relaxed) as u128;
        stats.transitive_dispatched = self.transitive_dispatched.load(Relaxed);
        stats.max_depth_reached = self.max_depth_reached.load(Relaxed);
        stats.no_version_match = self.no_version_match.load(Relaxed);
        stats.unresolved_parked = self.unresolved_parked.load(Relaxed);
    }
}

async fn run_deep_batch_with_speculation(
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    semaphore: &Arc<Semaphore>,
    coord: &Arc<FetchCoordinator>,
    deps: &HashMap<String, String>,
    dep_names: &[String],
) -> Result<
    (
        HashMap<String, lpm_registry::PackageMetadata>,
        SpeculativeJoin,
    ),
    LpmError,
> {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

    let started_at = std::time::Instant::now();

    // Channel capacity: room for every manifest in a typical deep tree.
    // The dispatcher drains the channel as fast as tokio schedules it,
    // so the buffer is primarily protection against very short bursts,
    // not a backpressure lever. 512 covers most trees comfortably; very
    // large monorepos may see the parser briefly await on send.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, lpm_registry::PackageMetadata)>(512);

    let deps_for_spec = deps.clone();
    let client_spec = client.clone();
    let store_spec = store.clone();
    let sem_spec = semaphore.clone();
    let coord_spec = coord.clone();

    let dispatched = Arc::new(AtomicU64::new(0));
    let completed = Arc::new(AtomicU64::new(0));
    let task_ms_sum = Arc::new(AtomicU64::new(0));
    let transitive_dispatched = Arc::new(AtomicU64::new(0));
    let max_depth_reached = Arc::new(AtomicU64::new(0));
    let no_version_match = Arc::new(AtomicU64::new(0));
    let unresolved_parked = Arc::new(AtomicU64::new(0));

    let dispatched_c = dispatched.clone();
    let completed_c = completed.clone();
    let task_ms_c = task_ms_sum.clone();
    let transitive_c = transitive_dispatched.clone();
    let max_depth_c = max_depth_reached.clone();
    let no_match_c = no_version_match.clone();
    let parked_c = unresolved_parked.clone();

    let dispatcher = tokio::spawn(async move {
        // Work queue items: (package_name, range_string, depth, is_root).
        // Depth is 1 for roots, N+1 for each transitive hop. Capped at
        // SPECULATION_MAX_DEPTH.
        let mut work_queue: Vec<(String, String, u32, bool)> = Vec::new();
        // Packages whose manifest has arrived.
        let mut metadata: HashMap<String, lpm_registry::PackageMetadata> = HashMap::new();
        // Ranges waiting on a specific package's manifest to arrive.
        // Keyed by package name; values are (range, depth, is_root).
        let mut parked: HashMap<String, Vec<(String, u32, bool)>> = HashMap::new();
        // "name@version" that have already been dispatched; dedups
        // re-asks for the same pinned version from multiple parents.
        let mut already_dispatched: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut spec_tasks = Vec::new();

        // Seed roots.
        for (name, range) in &deps_for_spec {
            work_queue.push((name.clone(), range.clone(), 1, true));
        }

        // Process-one-item helper. Inlined so it can mutate the
        // dispatcher-local state without awkward borrow splits.
        let process_item =
            |name: String,
             range: String,
             depth: u32,
             is_root: bool,
             metadata: &HashMap<String, lpm_registry::PackageMetadata>,
             parked: &mut HashMap<String, Vec<(String, u32, bool)>>,
             already_dispatched: &mut std::collections::HashSet<String>,
             work_queue: &mut Vec<(String, String, u32, bool)>,
             spec_tasks: &mut Vec<tokio::task::JoinHandle<()>>| {
                let Some(meta) = metadata.get(&name) else {
                    parked
                        .entry(name)
                        .or_default()
                        .push((range, depth, is_root));
                    return;
                };

                let Some((version, url, integrity)) = pick_speculative_version(meta, &range) else {
                    // Range didn't match any arrived version — count it so we
                    // can tell "dispatcher worked but range was too tight"
                    // apart from "dispatcher never saw this package".
                    no_match_c.fetch_add(1, Relaxed);
                    return;
                };

                let key = format!("{name}@{version}");
                if !already_dispatched.insert(key.clone()) {
                    return;
                }

                // Already-in-store: free store hit, no speculation needed.
                if store_spec.has_package(&name, &version) {
                    return;
                }

                // Record depth high-water mark + transitive flag.
                let current_max = max_depth_c.load(Relaxed);
                if depth as u64 > current_max {
                    max_depth_c.store(depth as u64, Relaxed);
                }
                dispatched_c.fetch_add(1, Relaxed);
                if !is_root {
                    transitive_c.fetch_add(1, Relaxed);
                }

                // Expand transitive deps onto the work queue (bounded by
                // SPECULATION_MAX_DEPTH). Uses the chosen version's
                // `dependencies` map — `dev` / `peer` / `optional` are out
                // of scope because npm's install-time graph only chases
                // production deps. Matches what PubGrub walks for
                // production installs.
                if depth < SPECULATION_MAX_DEPTH
                    && let Some(vm) = meta.versions.get(&version)
                {
                    for (dep_name, dep_range) in &vm.dependencies {
                        work_queue.push((dep_name.clone(), dep_range.clone(), depth + 1, false));
                    }
                }

                // Spawn the download.
                let c = client_spec.clone();
                let s = store_spec.clone();
                let sem = sem_spec.clone();
                let coord = coord_spec.clone();
                let completed_task = completed_c.clone();
                let task_ms_task = task_ms_c.clone();
                spec_tasks.push(tokio::spawn(async move {
                let task_start = std::time::Instant::now();
                match speculative_download_and_store(
                    &c,
                    &s,
                    &sem,
                    &coord,
                    &name,
                    &version,
                    &url,
                    integrity.as_deref(),
                )
                .await
                {
                    Ok(()) => {
                        completed_task.fetch_add(1, Relaxed);
                    }
                    Err(e) => {
                        tracing::debug!(
                            "speculative download {name}@{version} failed (will be retried by real fetch): {e}"
                        );
                    }
                }
                task_ms_task.fetch_add(task_start.elapsed().as_millis() as u64, Relaxed);
            }));
            };

        // Main interleave loop: drain the work queue, then wait for the
        // next manifest, unpark any pending ranges that were keyed on
        // it, and repeat.
        loop {
            while let Some((name, range, depth, is_root)) = work_queue.pop() {
                process_item(
                    name,
                    range,
                    depth,
                    is_root,
                    &metadata,
                    &mut parked,
                    &mut already_dispatched,
                    &mut work_queue,
                    &mut spec_tasks,
                );
            }

            match rx.recv().await {
                Some((name, meta)) => {
                    metadata.insert(name.clone(), meta);
                    if let Some(pending) = parked.remove(&name) {
                        for (range, depth, is_root) in pending {
                            work_queue.push((name.clone(), range, depth, is_root));
                        }
                    }
                }
                None => break, // sender dropped → RPC complete
            }
        }

        // Drain any remaining work (possible if a manifest arrived
        // immediately before the sender dropped).
        while let Some((name, range, depth, is_root)) = work_queue.pop() {
            process_item(
                name,
                range,
                depth,
                is_root,
                &metadata,
                &mut parked,
                &mut already_dispatched,
                &mut work_queue,
                &mut spec_tasks,
            );
        }

        // Packages still parked here were expected by some parent but
        // their manifest never arrived in the batch — the worker's
        // deep-walk didn't reach them. Report so we can tune the
        // server-side cap if this becomes common.
        let orphan_count: u64 = parked.values().map(|v| v.len() as u64).sum();
        parked_c.fetch_add(orphan_count, Relaxed);

        // Wait for all dispatched speculations to either complete or
        // drop — ensures store visibility for the real fetch loop's
        // `has_package` check. Losing a race to the real loop is fine:
        // the store's atomic-rename protects against corruption.
        futures::future::join_all(spec_tasks).await;
    });

    let batch = client.batch_metadata_deep_streaming(dep_names, tx).await?;
    // Crucial for P3 overlap: do NOT await `dispatcher` here. The sender
    // drops when `batch_metadata_deep_streaming` returns, so the
    // dispatcher's `rx.recv()` loop exits — but dispatched speculative
    // downloads continue running on the tokio runtime. Caller awaits the
    // `SpeculativeJoin` after resolver CPU, overlapping the two.
    Ok((
        batch,
        SpeculativeJoin {
            handle: dispatcher,
            started_at,
            dispatched,
            completed,
            task_ms_sum,
            transitive_dispatched,
            max_depth_reached,
            no_version_match,
            unresolved_parked,
        },
    ))
}

/// Phase 38 P3: one speculative download — stream tarball → store,
/// identical to `fetch_and_store_streaming` but without the
/// `InstallPackage`-shaped plumbing or `TaskTimings` accounting. Errors
/// are swallowed by the dispatcher (best-effort speculation); the real
/// fetch loop remains the authority.
#[allow(clippy::too_many_arguments)]
async fn speculative_download_and_store(
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    semaphore: &Arc<Semaphore>,
    coord: &Arc<FetchCoordinator>,
    name: &str,
    version: &str,
    url: &str,
    integrity: Option<&str>,
) -> Result<(), LpmError> {
    use futures::stream::TryStreamExt;
    use tokio_util::io::{StreamReader, SyncIoBridge};

    // Phase 39 P2: per-key fetch lock. The real fetch loop may target
    // the same `(name, version)` if spec and resolver agree on the
    // version. First task through wins the lock, does the download +
    // atomic rename; any sibling waits and short-circuits on the
    // `has_package` hit below. Acquired BEFORE the download semaphore
    // so the permit is released as soon as the sibling skip-path sees
    // the package and returns — no network contention on the duplicate.
    let key_lock = coord.lock_for(name, version).await;
    let _key_guard = key_lock.lock().await;

    if store.has_package(name, version) {
        return Ok(());
    }

    let _permit = semaphore
        .acquire()
        .await
        .map_err(|_| LpmError::Registry("spec semaphore closed".into()))?;

    let response = client.download_tarball_streaming(url).await?;
    let byte_stream = response.bytes_stream().map_err(std::io::Error::other);
    let async_reader = StreamReader::new(byte_stream);

    let name_c = name.to_string();
    let version_c = version.to_string();
    let integrity_c = integrity.map(|s| s.to_string());
    let store_owned = store.clone();

    tokio::task::spawn_blocking(move || {
        let sync_reader = SyncIoBridge::new(async_reader);
        store_owned
            .stream_and_store_package(
                &name_c,
                &version_c,
                sync_reader,
                integrity_c.as_deref(),
                lpm_registry::MAX_COMPRESSED_TARBALL_SIZE,
            )
            .map(|_| ())
    })
    .await
    .map_err(|e| LpmError::Registry(format!("spec blocking task: {e}")))??;
    Ok(())
}

/// Resolve the tarball URL for a package, consulting registry metadata
/// only when the resolver didn't already cache one. Shared by both the
/// legacy (temp-file) and Phase 38 P1 (streaming) fetch paths.
async fn resolve_tarball_url(
    client: &Arc<RegistryClient>,
    name: &str,
    version: &str,
    is_lpm: bool,
    cached_url: Option<&str>,
) -> Result<String, LpmError> {
    if let Some(url) = cached_url {
        return Ok(url.to_string());
    }
    if is_lpm {
        let pkg =
            lpm_common::PackageName::parse(name).map_err(|e| LpmError::Registry(e.to_string()))?;
        let metadata = client.get_package_metadata(&pkg).await?;
        let ver_meta = metadata
            .version(version)
            .ok_or_else(|| LpmError::NotFound(format!("{name}@{version} not found in metadata")))?;
        return Ok(ver_meta
            .tarball_url()
            .ok_or_else(|| LpmError::NotFound(format!("no tarball URL for {name}@{version}")))?
            .to_string());
    }
    let metadata = client.get_npm_package_metadata(name).await?;
    let ver_meta = metadata
        .version(version)
        .ok_or_else(|| LpmError::NotFound(format!("{name}@{version} not found in metadata")))?;
    Ok(ver_meta
        .tarball_url()
        .ok_or_else(|| LpmError::NotFound(format!("no tarball URL for {name}@{version}")))?
        .to_string())
}

/// Shared 404-handling: when a tarball URL 404s and the same-run
/// retry can't recover it either, the metadata cache is stale —
/// nuke the lockfiles so the next `lpm install` re-resolves and
/// re-fetches from fresh metadata. Returns the user-facing error
/// message the caller should surface.
///
/// **Phase 43 P43-2 fix:** takes `project_dir` and resolves lockfile
/// paths via `project_dir.join(...)` instead of `Path::new(...)`
/// (which was CWD-relative). A programmatic caller running install
/// from a nested directory previously left the actual project
/// lockfiles untouched, leaking stale state on retry.
fn handle_tarball_not_found(
    client: &Arc<RegistryClient>,
    name: &str,
    version: &str,
    project_dir: &Path,
) -> LpmError {
    client.invalidate_metadata_cache(name);
    let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if lock_path.exists() {
        let _ = std::fs::remove_file(&lock_path);
    }
    let lockb_path = project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME);
    if lockb_path.exists() {
        let _ = std::fs::remove_file(&lockb_path);
    }
    LpmError::NotFound(format!(
        "{name}@{version} tarball not found (possibly unpublished). \
         Cache cleared — run `lpm install` again to re-resolve."
    ))
}

/// Legacy fetch path — download to temp file, reopen, extract. Returns
/// `(computed_sri, TaskTimings)`. Called from the per-task closure under
/// a held download semaphore permit. Kept as the default while Phase 38
/// P1's streaming path is validated.
///
/// **Phase 43 P43-2.** `project_dir` + `gate_stats` are threaded in
/// for the CWD-safe `handle_tarball_not_found` (which deletes
/// lockfiles relative to the project root, not CWD) and the
/// stale-URL same-run retry telemetry. See the design doc §P43-2
/// Change 2 for the full retry semantics.
async fn fetch_and_store_legacy(
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    p: &InstallPackage,
    queue_wait_ms: u128,
    project_dir: &Path,
    gate_stats: &Arc<GateStats>,
) -> Result<(String, TaskTimings, String), LpmError> {
    use std::sync::atomic::Ordering;

    // Phase 43 — explicit URL resolution + download so we can
    // distinguish a metadata 404 (truly unpublished, no retry) from
    // a download 404 on a stored URL (stale cached URL, try
    // recovery). Return tuple's final `String` is the URL that
    // served bytes (equal to `initial_url` on the happy path, the
    // retry's `fresh_url` on stale-URL recovery). Driver post-
    // aggregates any divergence from `p.tarball_url` into the
    // writeback `fresh_urls` map.
    let url_lookup_start = std::time::Instant::now();
    let initial_url = match resolve_tarball_url(
        client,
        &p.name,
        &p.version,
        p.is_lpm,
        p.tarball_url.as_deref(),
    )
    .await
    {
        Ok(u) => u,
        Err(LpmError::NotFound(_)) => {
            // Metadata 404 — package/version genuinely gone.
            // Nothing to retry.
            return Err(handle_tarball_not_found(
                client,
                &p.name,
                &p.version,
                project_dir,
            ));
        }
        Err(e) => return Err(e),
    };
    let mut url_lookup_ms = url_lookup_start.elapsed().as_millis();
    let mut final_url = initial_url.clone();

    let download_start = std::time::Instant::now();
    let downloaded = match client.download_tarball_to_file(&initial_url).await {
        Ok(r) => r,
        Err(LpmError::NotFound(_)) if p.tarball_url.is_some() => {
            // Stored URL went stale — package was republished, or
            // upstream migrated paths. Invalidate metadata + retry
            // ONCE with a freshly-resolved URL.
            client.invalidate_metadata_cache(&p.name);
            let retry_lookup_start = std::time::Instant::now();
            let fresh_url =
                match resolve_tarball_url(client, &p.name, &p.version, p.is_lpm, None).await {
                    Ok(u) => u,
                    Err(_) => {
                        gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                        return Err(handle_tarball_not_found(
                            client,
                            &p.name,
                            &p.version,
                            project_dir,
                        ));
                    }
                };
            url_lookup_ms += retry_lookup_start.elapsed().as_millis();
            if fresh_url == initial_url {
                // Loop guard — metadata still points at the same
                // stale URL. Tarball is really gone, not just moved.
                gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                return Err(handle_tarball_not_found(
                    client,
                    &p.name,
                    &p.version,
                    project_dir,
                ));
            }
            match client.download_tarball_to_file(&fresh_url).await {
                Ok(r) => {
                    gate_stats.stale_recovery.fetch_add(1, Ordering::Relaxed);
                    final_url = fresh_url;
                    r
                }
                Err(LpmError::NotFound(_)) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Err(LpmError::NotFound(_)) => {
            // On-demand path (no stored URL) 404 — really gone.
            return Err(handle_tarball_not_found(
                client,
                &p.name,
                &p.version,
                project_dir,
            ));
        }
        Err(e) => return Err(e),
    };
    // Phase 43 — `download_ms` measures just the GET + temp-file
    // write. URL-lookup costs (initial + optional retry) are
    // accumulated into `url_lookup_ms` above.
    let download_ms = download_start.elapsed().as_millis();

    let computed_sri = downloaded.sri.clone();

    // Verify integrity before storing. SHA-512 is the common case: computed
    // during download, so match is a string compare. Non-sha512 expected
    // values stream-verify from the temp file in 64 KB chunks.
    let integrity_start = std::time::Instant::now();
    if let Some(ref integrity) = p.integrity {
        if computed_sri != *integrity
            && let Err(e) = lpm_extractor::verify_integrity_file(downloaded.file.path(), integrity)
        {
            return Err(LpmError::Registry(format!(
                "integrity verification failed for {}@{}: {e}",
                p.name, p.version
            )));
        }
    } else {
        tracing::warn!(
            "no integrity hash for {}@{} — skipping verification",
            p.name,
            p.version
        );
    }
    let integrity_ms = integrity_start.elapsed().as_millis();

    let (_, stage) = store.store_package_from_file_timed(
        &p.name,
        &p.version,
        downloaded.file.path(),
        &computed_sri,
    )?;

    Ok((
        computed_sri,
        TaskTimings {
            queue_wait_ms,
            url_lookup_ms,
            download_ms,
            integrity_ms,
            extract_ms: stage.extract_ms,
            security_ms: stage.security_ms,
            finalize_ms: stage.finalize_ms,
        },
        final_url,
    ))
}

/// Phase 38 P1 streaming fetch path — bytes flow from reqwest directly
/// into the store's extractor via `StreamReader` + `SyncIoBridge`. No
/// temp file spool, no re-read. Hash computed inline as bytes flow.
///
/// Because download + decode + extract + hash happen in one interleaved
/// pipeline, `download_ms` and `integrity_ms` collapse into
/// `extract_ms` — the breakdown stays shape-compatible with the legacy
/// path but pushes mass into one bucket. That's the whole point of P1:
/// eliminate the temp-file hop that today forces sequential download →
/// reopen → extract.
async fn fetch_and_store_streaming(
    client: &Arc<RegistryClient>,
    store: &PackageStore,
    p: &InstallPackage,
    queue_wait_ms: u128,
    project_dir: &Path,
    gate_stats: &Arc<GateStats>,
) -> Result<(String, TaskTimings, String), LpmError> {
    use futures::stream::TryStreamExt;
    use std::sync::atomic::Ordering;
    use tokio_util::io::{StreamReader, SyncIoBridge};

    // URL resolution — Phase 43 times this into `url_lookup_ms` and
    // distinguishes metadata 404 (truly unpublished, no retry) from
    // a download 404 on a stored URL (stale cache, try recovery).
    let url_lookup_start = std::time::Instant::now();
    let initial_url = match resolve_tarball_url(
        client,
        &p.name,
        &p.version,
        p.is_lpm,
        p.tarball_url.as_deref(),
    )
    .await
    {
        Ok(u) => u,
        Err(LpmError::NotFound(_)) => {
            return Err(handle_tarball_not_found(
                client,
                &p.name,
                &p.version,
                project_dir,
            ));
        }
        Err(e) => return Err(e),
    };
    let mut url_lookup_ms = url_lookup_start.elapsed().as_millis();
    let mut final_url = initial_url.clone();

    let response = match client.download_tarball_streaming(&initial_url).await {
        Ok(r) => r,
        Err(LpmError::NotFound(_)) if p.tarball_url.is_some() => {
            // Stored URL stale — retry ONCE with fresh metadata.
            // See `fetch_and_store_legacy` for the full semantics;
            // this branch mirrors that retry logic byte-for-byte
            // (minus the streaming-specific response handling).
            client.invalidate_metadata_cache(&p.name);
            let retry_lookup_start = std::time::Instant::now();
            let fresh_url =
                match resolve_tarball_url(client, &p.name, &p.version, p.is_lpm, None).await {
                    Ok(u) => u,
                    Err(_) => {
                        gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                        return Err(handle_tarball_not_found(
                            client,
                            &p.name,
                            &p.version,
                            project_dir,
                        ));
                    }
                };
            url_lookup_ms += retry_lookup_start.elapsed().as_millis();
            if fresh_url == initial_url {
                gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                return Err(handle_tarball_not_found(
                    client,
                    &p.name,
                    &p.version,
                    project_dir,
                ));
            }
            match client.download_tarball_streaming(&fresh_url).await {
                Ok(r) => {
                    gate_stats.stale_recovery.fetch_add(1, Ordering::Relaxed);
                    final_url = fresh_url;
                    r
                }
                Err(LpmError::NotFound(_)) => {
                    gate_stats.stale_hard_fail.fetch_add(1, Ordering::Relaxed);
                    return Err(handle_tarball_not_found(
                        client,
                        &p.name,
                        &p.version,
                        project_dir,
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Err(LpmError::NotFound(_)) => {
            return Err(handle_tarball_not_found(
                client,
                &p.name,
                &p.version,
                project_dir,
            ));
        }
        Err(e) => return Err(e),
    };

    // Adapt reqwest's `Result<Bytes, reqwest::Error>` stream into the
    // `Result<Bytes, io::Error>` shape `StreamReader` requires. The
    // `SyncIoBridge` then exposes that async reader as a blocking `Read`
    // for the sync extractor.
    let byte_stream = response.bytes_stream().map_err(std::io::Error::other);
    let async_reader = StreamReader::new(byte_stream);

    let name = p.name.clone();
    let version = p.version.clone();
    let expected_integrity = p.integrity.clone();
    let store_owned = store.clone();

    // Everything below runs on the blocking pool — frees the tokio async
    // workers to keep driving network reads. The semaphore permit the
    // caller holds is still effectively held across this blocking call
    // (spawn_blocking's JoinHandle is awaited).
    let extract_start = std::time::Instant::now();
    let (computed_sri, stage) = tokio::task::spawn_blocking(move || {
        let sync_reader = SyncIoBridge::new(async_reader);
        store_owned
            .stream_and_store_package(
                &name,
                &version,
                sync_reader,
                expected_integrity.as_deref(),
                lpm_registry::MAX_COMPRESSED_TARBALL_SIZE,
            )
            .map(|(_path, sri, timings)| (sri, timings))
    })
    .await
    .map_err(|e| LpmError::Registry(format!("streaming extract task panicked: {e}")))??;
    let pipeline_ms = extract_start.elapsed().as_millis();

    // The store's `stage.extract_ms` is the exact same measurement as
    // `pipeline_ms` (both cover the spawn_blocking body) — we prefer the
    // inner number because it excludes the join overhead. Keep
    // `download_ms` and `integrity_ms` at zero so sums stay truthful: the
    // work is in `extract_ms` on this path by design.
    let _ = pipeline_ms; // retained for future diagnostic instrumentation

    Ok((
        computed_sri,
        TaskTimings {
            queue_wait_ms,
            url_lookup_ms,
            download_ms: 0,
            integrity_ms: 0,
            extract_ms: stage.extract_ms,
            security_ms: stage.security_ms,
            finalize_ms: stage.finalize_ms,
        },
        final_url,
    ))
}

/// Phase 33 placeholder spec written into the manifest by
/// [`stage_packages_to_manifest`] for entries whose final spec depends on
/// the resolved version. The full install pipeline sees this as "any
/// version", resolves it normally, and [`finalize_packages_in_manifest`]
/// then replaces it with the resolved-version-derived spec.
///
/// This string MUST be a valid `node_semver` range so the resolver
/// accepts it. `*` is the canonical "any version" spec.
const STAGE_PLACEHOLDER: &str = "*";

/// Outcome of staging a single dependency into the manifest.
#[derive(Debug, Clone)]
pub(crate) enum StagedKind {
    /// Stage wrote the user's verbatim explicit spec (Exact / Range /
    /// Wildcard / Workspace). Finalize is a no-op.
    Final,
    /// Stage wrote the [`STAGE_PLACEHOLDER`]. Finalize must replace it
    /// with `decide_saved_dependency_spec(intent, resolved, flags, config)`.
    Placeholder,
    /// Stage left the manifest untouched because the dep already exists
    /// and the bare reinstall came with no rewrite-forcing flag. Phase 33
    /// "no churn" rule. Finalize is a no-op.
    Skipped,
}

/// Per-package record produced by [`stage_packages_to_manifest`].
#[derive(Debug, Clone)]
pub(crate) struct StagedEntry {
    pub name: String,
    pub intent: crate::save_spec::UserSaveIntent,
    pub kind: StagedKind,
}

/// Snapshot of one manifest's stage step. Returned to the caller so the
/// finalize step can replay the per-entry decisions after resolution.
#[derive(Debug, Clone)]
pub(crate) struct StagedManifest {
    pub pkg_json_path: PathBuf,
    pub save_dev: bool,
    pub entries: Vec<StagedEntry>,
}

impl StagedManifest {
    /// Whether this stage produced any placeholders that finalize must
    /// rewrite. Used by callers to skip the finalize re-read entirely
    /// when nothing was placeheld.
    pub fn has_placeholders(&self) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e.kind, StagedKind::Placeholder))
    }
}

/// **Phase 33 stage step.** Mutate `pkg_json_path` to reflect the user's
/// install request as far as it can be determined without running the
/// resolver, and return a [`StagedManifest`] describing what still needs
/// to be patched after resolution.
///
/// Per-entry behavior:
///
/// - **Explicit user input** ([`UserSaveIntent::Exact`],
///   [`UserSaveIntent::Range`], [`UserSaveIntent::Wildcard`],
///   [`UserSaveIntent::Workspace`]) — write the verbatim string. Finalize
///   skips these.
/// - **Bare or dist-tag**, dep already in target dep table, no
///   rewrite-forcing flag — leave the manifest entry alone (Phase 33
///   "no-churn" rule). Finalize skips these.
/// - **Bare or dist-tag**, otherwise — write [`STAGE_PLACEHOLDER`] so the
///   resolver picks up the new dep. Finalize will replace it with the
///   final save spec once the resolved version is known.
///
/// Reads → mutates → atomically rewrites the manifest in one go. Does
/// NOT touch the lockfile, the install pipeline, or any other manifest.
/// The caller is expected to wrap this call (and the install pipeline +
/// finalize) in a [`crate::manifest_tx::ManifestTransaction`] so a failed
/// install rolls the manifest bytes back to their pre-stage state.
///
/// Returns `Err(LpmError::NotFound)` if the manifest is missing,
/// `Err(LpmError::Registry)` for parse/serialize failures.
pub(crate) fn stage_packages_to_manifest(
    pkg_json_path: &Path,
    package_specs: &[String],
    save_dev: bool,
    flags: crate::save_spec::SaveFlags,
    json_output: bool,
) -> Result<StagedManifest, LpmError> {
    use crate::save_spec::{UserSaveIntent, parse_user_save_intent};

    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(format!(
            "no package.json at {}",
            pkg_json_path.display()
        )));
    }

    let content = std::fs::read_to_string(pkg_json_path)?;
    let mut doc: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let dep_key = if save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };

    if doc.get(dep_key).is_none() {
        doc[dep_key] = serde_json::json!({});
    }

    let target_label = pkg_json_path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| pkg_json_path.display().to_string());

    let force_rewrite = flags.forces_rewrite();
    let mut entries: Vec<StagedEntry> = Vec::with_capacity(package_specs.len());
    // Track whether `doc` has been mutated. Phase 33 no-churn rule: when
    // every spec hits the Skipped branch, we must NOT rewrite the file —
    // re-serializing through serde_json::to_string_pretty would normalize
    // indentation and add a trailing newline, which counts as a manifest
    // mutation and trips the placeholder-survival invariant.
    let mut doc_mutated = false;

    for spec in package_specs {
        let (name, intent) = parse_user_save_intent(spec);

        // Tier 1: explicit user input → write verbatim, mark Final.
        let explicit_literal: Option<String> = match &intent {
            UserSaveIntent::Wildcard => Some("*".to_string()),
            UserSaveIntent::Exact(s) | UserSaveIntent::Range(s) | UserSaveIntent::Workspace(s) => {
                Some(s.clone())
            }
            UserSaveIntent::Bare | UserSaveIntent::DistTag(_) => None,
        };

        if let Some(literal) = explicit_literal {
            if !json_output {
                output::info(&format!(
                    "Adding {}@{} to {} ({target_label})",
                    name.bold(),
                    literal,
                    dep_key
                ));
            }
            doc[dep_key][&name] = serde_json::Value::String(literal);
            doc_mutated = true;
            entries.push(StagedEntry {
                name,
                intent,
                kind: StagedKind::Final,
            });
            continue;
        }

        // Tier 2: bare reinstall of an existing dep with no rewrite-forcing
        // flag → skip (Phase 33 no-churn rule).
        //
        // **Audit Finding 3:** dist-tag intents (`react@latest`, `@beta`,
        // `@next`) are NOT eligible for this skip even when the dep is
        // already present. The user explicitly typed a tag, which is a
        // request to re-resolve under that tag and save the new policy-
        // derived spec. Only the truly-bare `lpm install <name>` form
        // counts as "no churn" — that's a refresh of lockfile/store state.
        let is_bare_reinstall = matches!(intent, UserSaveIntent::Bare);
        let already_present = doc
            .get(dep_key)
            .and_then(|v| v.get(&name))
            .and_then(|v| v.as_str())
            .is_some();
        if is_bare_reinstall && already_present && !force_rewrite {
            if !json_output {
                output::info(&format!(
                    "Refreshing {} in {} ({target_label}) — keeping existing range",
                    name.bold(),
                    dep_key
                ));
            }
            entries.push(StagedEntry {
                name,
                intent,
                kind: StagedKind::Skipped,
            });
            continue;
        }

        // Tier 3: bare/dist-tag without an existing entry, OR an existing
        // entry that the user explicitly opted to rewrite via a flag.
        // Stage a placeholder; finalize will replace it after the resolver
        // returns the concrete version.
        if !json_output {
            output::info(&format!(
                "Adding {} to {} ({target_label})",
                name.bold(),
                dep_key
            ));
        }
        doc[dep_key][&name] = serde_json::Value::String(STAGE_PLACEHOLDER.to_string());
        doc_mutated = true;
        entries.push(StagedEntry {
            name,
            intent,
            kind: StagedKind::Placeholder,
        });
    }

    // Only rewrite the file if we actually changed the document. The
    // all-Skipped path leaves the manifest exactly as the user wrote it,
    // including their original whitespace and trailing newline (or lack
    // thereof). This is what the row 12 no-churn workflow test asserts
    // byte-for-byte.
    if doc_mutated {
        let updated =
            serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
        std::fs::write(pkg_json_path, format!("{updated}\n"))?;
    }

    Ok(StagedManifest {
        pkg_json_path: pkg_json_path.to_path_buf(),
        save_dev,
        entries,
    })
}

/// **Phase 33 audit Finding 1 fix.** Build a `name → Version` map for
/// every direct dependency in the resolver's output. Used by Phase 33's
/// finalize step to look up the resolved version of placeholder-staged
/// deps without ambiguity.
///
/// Why this lives next to the install pipeline (not next to the
/// lockfile reader): the resolver's `InstallPackage` struct already
/// carries `is_direct: bool`, computed from membership in the staged
/// manifest's `dependencies` map. Reading the same information from the
/// on-disk lockfile post-install would require either a lockfile-format
/// extension (the lockfile has no direct/transitive flag) or a
/// vulnerable-to-collision flat name scan over `lockfile.packages` —
/// the audit's Finding 1.
///
/// This function trusts the resolver's `is_direct` and ignores every
/// transitive entry. If the same name appears as direct more than once
/// (which would be a resolver bug, not a Phase 33 bug), the LAST entry
/// wins and we log a warning.
///
/// Returns an empty map if `packages` is empty or has no direct entries.
fn collect_direct_versions(packages: &[InstallPackage]) -> HashMap<String, lpm_semver::Version> {
    let mut map = HashMap::new();
    for p in packages.iter().filter(|p| p.is_direct) {
        match lpm_semver::Version::parse(&p.version) {
            Ok(v) => {
                if map.insert(p.name.clone(), v).is_some() {
                    tracing::warn!(
                        "Phase 33: package `{}` appears as a direct dep more than once \
                         in resolver output — last entry wins. This indicates a resolver bug.",
                        p.name
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Phase 33: resolved version `{}` for direct dep `{}` did not parse \
                     as semver: {e}. Finalize will surface a missing-version error.",
                    p.version,
                    p.name
                );
            }
        }
    }
    map
}

/// **Phase 33 finalize step.** Replay the stage decisions against the
/// current manifest using the resolver's output, replacing any
/// [`STAGE_PLACEHOLDER`] entries with the final save spec computed by
/// [`crate::save_spec::decide_saved_dependency_spec`].
///
/// `resolved_versions` maps direct-dep names → the concrete version
/// the resolver picked. Entries marked [`StagedKind::Placeholder`] that
/// are missing from this map are treated as "the resolver dropped them",
/// which is a hard error: the install pipeline succeeded but failed to
/// resolve a top-level dep, which would silently leave a `*` in the
/// manifest. Better to surface it.
///
/// Reads the manifest fresh from disk so any unrelated edits the install
/// pipeline made (it doesn't make any today, but this future-proofs us)
/// are preserved. Atomic rewrite, same pretty-print conventions as stage.
///
/// Skips entirely if [`StagedManifest::has_placeholders`] is `false` —
/// nothing to do, and we avoid the read/write round-trip.
pub(crate) fn finalize_packages_in_manifest(
    staged: &StagedManifest,
    resolved_versions: &HashMap<String, lpm_semver::Version>,
    flags: crate::save_spec::SaveFlags,
    config: crate::save_spec::SaveConfig,
) -> Result<(), LpmError> {
    if !staged.has_placeholders() {
        return Ok(());
    }

    let content = std::fs::read_to_string(&staged.pkg_json_path)?;
    let mut doc: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let dep_key = if staged.save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };

    for entry in &staged.entries {
        if !matches!(entry.kind, StagedKind::Placeholder) {
            continue;
        }

        let resolved = resolved_versions.get(&entry.name).ok_or_else(|| {
            LpmError::Registry(format!(
                "Phase 33 finalize: resolver did not report a concrete version for `{}` \
                 (staged with placeholder `{STAGE_PLACEHOLDER}`). Refusing to leave the \
                 placeholder in {}.",
                entry.name,
                staged.pkg_json_path.display(),
            ))
        })?;

        let decision =
            crate::save_spec::decide_saved_dependency_spec(&entry.intent, resolved, flags, config)?;

        doc[dep_key][&entry.name] = serde_json::Value::String(decision.spec_to_write);
    }

    let updated =
        serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
    std::fs::write(&staged.pkg_json_path, format!("{updated}\n"))?;
    Ok(())
}

/// Install specific packages: add them to package.json then run full install.
/// For Swift packages (ecosystem=swift), uses SE-0292 registry mode instead.
///
/// Handles specs like: `express`, `express@^4.0.0`, `@lpm.dev/neo.highlight@1.0.0`
///
/// **Phase 32 Phase 2 M2:** this is the legacy path used when no `--filter`
/// or `-w` flag is set AND we're not inside a workspace member directory.
/// New filtered paths go through `run_install_filtered_add` instead, which
/// handles workspace-aware target resolution but rejects Swift packages
/// (SE-0292 workspace support is deferred to Phase 12+).
///
/// **Phase 33:** `save_flags` carries the per-command save-spec overrides
/// (`--exact`, `--tilde`, `--save-prefix`). They flow through stage and
/// finalize so the manifest write reflects the user's explicit policy.
#[allow(clippy::too_many_arguments)]
pub async fn run_add_packages(
    client: &RegistryClient,
    project_dir: &Path,
    packages: &[String],
    save_dev: bool,
    json_output: bool,
    allow_new: bool,
    force: bool,
    save_flags: crate::save_spec::SaveFlags,
) -> Result<(), LpmError> {
    // First pass: check if any LPM packages are Swift ecosystem
    // Route Swift packages to SE-0292 registry mode
    let mut js_packages = Vec::new();

    for spec in packages {
        let (name, intent) = crate::save_spec::parse_user_save_intent(spec);
        let range = intent_to_range_string(&intent);

        if name.starts_with("@lpm.dev/") {
            // Fetch metadata to check ecosystem
            let pkg_name = lpm_common::PackageName::parse(&name)?;
            let metadata = client.get_package_metadata(&pkg_name).await?;
            let latest_ver = metadata
                .latest_version_tag()
                .ok_or_else(|| LpmError::NotFound(format!("no versions for {name}")))?;

            // Resolve the user-specified version range against available versions.
            // Falls back to latest when no version is specified.
            let resolved_ver = resolve_version_from_spec(&range, &metadata, latest_ver)?;
            let ver_meta = metadata.version(resolved_ver).ok_or_else(|| {
                LpmError::NotFound(format!("version {resolved_ver} not found for {name}"))
            })?;

            if ver_meta.effective_ecosystem() == "swift" {
                // SE-0292 registry mode
                run_swift_install(
                    project_dir,
                    &pkg_name,
                    resolved_ver,
                    ver_meta,
                    json_output,
                    client.base_url(),
                )
                .await?;
                continue;
            }
        }

        js_packages.push(spec.clone());
    }

    // If all packages were Swift, we're done
    if js_packages.is_empty() {
        return Ok(());
    }

    // ── Phase 33: stage → install → finalize, wrapped in a transaction
    // that covers the FULL install state surface. Audit Finding 2 fix:
    // snapshot the manifest AND the lockfile so a failed install rolls
    // both back together, and invalidate `.lpm/install-hash` so the next
    // install re-resolves and reconciles `node_modules/` (which we don't
    // snapshot — too large). ──────────────────────────────────────────
    let pkg_json_path = project_dir.join("package.json");
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let lockfile_bin_path = lockfile_path.with_extension("lockb");
    let install_hash_path = project_dir.join(".lpm").join("install-hash");

    // 1. Snapshot the install state surface. Manifest is required (must
    //    exist by precondition); lockfile + binary lockfile are optional
    //    (absent on a fresh project); install-hash is invalidate-only
    //    (cache file, deleted on rollback regardless of pre-state).
    let tx = crate::manifest_tx::ManifestTransaction::snapshot_install_state(
        &[&pkg_json_path],
        &[&lockfile_path, &lockfile_bin_path],
        &[&install_hash_path],
    )?;

    // 2. Stage the new entries. Explicit specs land verbatim; bare/dist-tag
    //    entries get a `*` placeholder that finalize will replace using the
    //    Phase 33 save policy (resolved version + flags + config).
    //
    //    Phase 33 Step 6: load `./lpm.toml` (project) merged with
    //    `~/.lpm/config.toml` (global) for the persistent save-policy
    //    keys. CLI flags still beat config inside `decide_saved_dependency_spec`.
    let save_config = crate::save_config::SaveConfigLoader::load_for_project(project_dir)?;
    let staged = stage_packages_to_manifest(
        &pkg_json_path,
        &js_packages,
        save_dev,
        save_flags,
        json_output,
    )?;

    // 3. Remove lockfile so the resolver re-runs against the staged manifest.
    //    The transaction snapshot above already captured the original bytes,
    //    so this delete is rolled back if the install pipeline fails.
    if lockfile_path.exists() {
        std::fs::remove_file(&lockfile_path)?;
    }

    // 4. Run the full install pipeline, capturing the direct-dep version
    //    map via the Phase 33 out-param. If anything fails, the `?`
    //    returns early — `tx` drops without `commit()` and the manifest
    //    snaps back to its pre-stage state. The placeholder never survives.
    let mut direct_versions: HashMap<String, lpm_semver::Version> = HashMap::new();
    run_with_options(
        client,
        project_dir,
        json_output,
        false, // offline
        force,
        allow_new,
        None,  // linker_override
        false, // no_skills
        false, // no_editor_setup
        false, // no_security_summary
        false, // auto_build
        None,  // target_set: legacy single-project path
        Some(&mut direct_versions),
    )
    .await?;

    // 5. Finalize the manifest using the resolved direct-dep versions
    //    from the resolver. No-op if stage produced no placeholders.
    finalize_packages_in_manifest(&staged, &direct_versions, save_flags, save_config)?;

    // 6. All steps succeeded — commit the transaction so the manifest
    //    edits persist.
    tx.commit();
    Ok(())
}

/// Phase 32 Phase 2 M2: workspace-aware install entry point.
///
/// Resolves CLI `--filter` / `-w` / cwd into a concrete set of
/// `package.json` files via [`crate::commands::install_targets`], mutates
/// each one with the requested package specs, then runs the install
/// pipeline ONCE at the resolved `install_root`.
///
/// **Swift packages**: this path treats every package as JS — Swift
/// `ecosystem=swift` packages added through this path will be written into
/// the target `package.json` files but the SE-0292 routing in
/// `run_swift_install` will not fire. Workspace-aware Swift install is
/// tracked under Phase 12+. For pure Swift workflows, use the legacy
/// path: `cd <project> && lpm install @scope/swift-pkg` (no `-w` / `--filter`).
///
/// **Phase 33:** `save_flags` carries the per-command save-spec overrides
/// applied to every targeted member's manifest finalize step.
#[allow(clippy::too_many_arguments)]
pub async fn run_install_filtered_add(
    client: &RegistryClient,
    cwd: &Path,
    packages: &[String],
    save_dev: bool,
    filters: &[String],
    workspace_root_flag: bool,
    fail_if_no_match: bool,
    yes: bool,
    json_output: bool,
    allow_new: bool,
    force: bool,
    save_flags: crate::save_spec::SaveFlags,
) -> Result<(), LpmError> {
    // 1. Resolve CLI flags into a concrete target list.
    let targets = crate::commands::install_targets::resolve_install_targets(
        cwd,
        filters,
        workspace_root_flag,
        true, // has_packages — install_filtered_add is only called with non-empty packages
    )?;

    // 2. Empty result handling (--fail-if-no-match mirrors Phase 1 D3).
    //
    // Phase 2 audit follow-through: when the filter set returns empty AND
    // any filter looks like a bare name that would have substring-matched
    // pre-Phase-32, surface the same D2 substring → glob migration hint
    // that `lpm run --filter` and `lpm filter` already emit. Otherwise
    // users coming from the legacy substring matcher get a generic "no
    // packages matched" with no recovery path.
    if targets.member_manifests.is_empty() {
        let hint = crate::commands::filter::format_no_match_hint(filters);

        if fail_if_no_match {
            let base = "no workspace packages matched the filter (--fail-if-no-match)";
            return Err(LpmError::Script(match hint {
                Some(h) => format!("{base}\n\n{h}"),
                None => base.to_string(),
            }));
        }
        if !json_output {
            output::warn("No packages matched the filter; nothing to install.");
            if let Some(h) = hint {
                eprintln!();
                for line in h.lines() {
                    eprintln!("  {}", line.dimmed());
                }
                eprintln!();
            }
        }
        return Ok(());
    }

    // 3. Multi-member confirmation prompt.
    //
    // **D-impl-5 (2026-04-16)** — the original Phase 2 plan included an
    // interactive y/N prompt gated on `multi_member && is_tty && !json_output`
    // and a `confirm_multi_member_mutation` helper. The implementation
    // initially shipped preview-only (no prompt); that gap is closed here.
    //
    // Contract:
    // - JSON mode: print the target set in the existing JSON payload, no
    //   prompt (agents get a single parseable result).
    // - Non-TTY stdin (CI, subprocess, redirected input): print preview, no
    //   prompt, proceed (legacy behavior preserved for scripts).
    // - `--yes` / `-y`: print preview, no prompt, proceed (scripts + agents
    //   that WANT the TTY branch but don't want to answer).
    // - Interactive TTY + not `--yes` + not JSON: print preview, ask
    //   "Proceed? [y/N]", default is No. User decline returns an error that
    //   halts BEFORE any `package.json` is touched.
    if targets.multi_member {
        confirm_multi_member_mutation(
            "Adding",
            packages.len(),
            &targets.member_manifests,
            yes,
            json_output,
        )?;
    }

    // 4. Iterate per target. For EACH targeted manifest:
    //    a. Mutate the manifest with the new package entries.
    //    b. Remove that member's lockfile to force re-resolution.
    //    c. Run the install pipeline AT THE MEMBER'S DIR (not at the
    //       workspace root). LPM uses per-directory lockfiles + node_modules,
    //       so this is the only place the new dependency will be installed
    //       and linked correctly.
    //
    // This is the Phase 2 audit correction. The original Phase 2 design ran
    // a single install pipeline at the workspace root, which silently
    // dropped member-targeted installs on workspaces with no root deps.
    //
    // For multi-target filtered installs (`--filter "ui-*"` matching N
    // members), the pipeline runs N times sequentially. JSON output mode
    // produces N JSON objects on stdout (JSON-Lines), one per member.
    let target_paths: Vec<String> = targets
        .member_manifests
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    // ── Phase 33: snapshot the FULL install state surface for every
    // targeted member in a single transaction. Audit Finding 2 fix:
    // each member contributes its own (manifest, lockfile, lockfile.b,
    // install-hash) quadruple. A failure halfway through a multi-member
    // install rolls every touched member back; earlier members'
    // node_modules trees are left as-is, but their install-hash files
    // are invalidated so the next `lpm install` re-resolves and
    // converges. ──────────────────────────────────────────────────────

    // Compute per-member install roots and the four state paths.
    let member_install_roots: Vec<PathBuf> = targets
        .member_manifests
        .iter()
        .map(|m| crate::commands::install_targets::install_root_for(m).to_path_buf())
        .collect();
    let lockfile_paths: Vec<PathBuf> = member_install_roots
        .iter()
        .map(|r| r.join(lpm_lockfile::LOCKFILE_NAME))
        .collect();
    let lockfile_bin_paths: Vec<PathBuf> = lockfile_paths
        .iter()
        .map(|p| p.with_extension("lockb"))
        .collect();
    let install_hash_paths: Vec<PathBuf> = member_install_roots
        .iter()
        .map(|r| r.join(".lpm").join("install-hash"))
        .collect();

    // Build the (required, optional, invalidate) reference slices the
    // transaction expects. `required` = manifests; `optional` = lockfile
    // + lockfile.b for every member; `invalidate` = install-hash for
    // every member.
    let required_refs: Vec<&Path> = targets
        .member_manifests
        .iter()
        .map(|p| p.as_path())
        .collect();
    let mut optional_refs: Vec<&Path> = Vec::with_capacity(lockfile_paths.len() * 2);
    for p in &lockfile_paths {
        optional_refs.push(p.as_path());
    }
    for p in &lockfile_bin_paths {
        optional_refs.push(p.as_path());
    }
    let invalidate_refs: Vec<&Path> = install_hash_paths.iter().map(|p| p.as_path()).collect();

    let tx = crate::manifest_tx::ManifestTransaction::snapshot_install_state(
        &required_refs,
        &optional_refs,
        &invalidate_refs,
    )?;

    // Phase 33: per-command save flags from the CLI flow into stage and
    // finalize so multi-member installs honor `--exact`/`--tilde`/etc.
    // for every targeted member identically.
    //
    // **Workspace-aware config resolution (audit Finding B fix):** the
    // project-tier `lpm.toml` MUST be read from the WORKSPACE ROOT, not
    // from `cwd`. Save policy is a workspace-wide preference; per-member
    // overrides would create incoherent multi-member installs where the
    // same `--filter "ui-*"` produces different prefixes per member.
    //
    // Pre-fix this read from `cwd` directly, which broke the moment a
    // user invoked `lpm install ms --filter app` from
    // `packages/app/` instead of from the workspace root: `cwd` was the
    // member dir, no `lpm.toml` lived there, and the loader silently
    // returned defaults. Now we walk up via `discover_workspace` and
    // pass the discovered root to the loader. Falls back to `cwd` only
    // when no workspace is discoverable (defensive — this path is only
    // reachable from a workspace context, but the fallback keeps the
    // loader call infallible if `discover_workspace` ever returns None
    // through some future code change).
    let workspace_root_for_config: PathBuf = lpm_workspace::discover_workspace(cwd)
        .ok()
        .flatten()
        .map(|ws| ws.root)
        .unwrap_or_else(|| cwd.to_path_buf());
    let save_config =
        crate::save_config::SaveConfigLoader::load_for_project(&workspace_root_for_config)?;

    let mut last_err: Option<LpmError> = None;
    for (idx, manifest_path) in targets.member_manifests.iter().enumerate() {
        // (a) Stage the target manifest. Explicit specs land verbatim;
        //     bare/dist-tag entries get a `*` placeholder.
        let staged = match stage_packages_to_manifest(
            manifest_path,
            packages,
            save_dev,
            save_flags,
            json_output,
        ) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e);
                break;
            }
        };

        // Use the precomputed install root + lockfile path so the
        // transaction snapshot above and the loop below agree on the
        // exact paths (no double-compute, no path drift).
        let install_root = &member_install_roots[idx];
        let lockfile_path = &lockfile_paths[idx];

        // (b) Remove this member's lockfile so the resolver re-runs.
        //     The transaction snapshot already captured the original
        //     bytes; the delete is rolled back if install fails below.
        if lockfile_path.exists()
            && let Err(e) = std::fs::remove_file(lockfile_path)
        {
            last_err = Some(LpmError::Io(e));
            break;
        }

        // (c) Run the install pipeline at THIS member's directory,
        //     capturing the direct-dep map for finalize via Phase 33's
        //     out-param.
        let mut direct_versions: HashMap<String, lpm_semver::Version> = HashMap::new();
        let result = run_with_options(
            client,
            install_root,
            json_output,
            false, // offline
            force,
            allow_new,
            None,  // linker_override
            false, // no_skills
            false, // no_editor_setup
            false, // no_security_summary
            false, // auto_build
            Some(&target_paths),
            Some(&mut direct_versions),
        )
        .await;

        if let Err(e) = result {
            // Abort on first failure. Half-installed multi-member states
            // are confusing and the user should fix the failure before
            // retrying. The transaction guard restores ALL touched
            // manifests when we drop without commit.
            last_err = Some(e);
            break;
        }

        // (d) Finalize this member's manifest using the direct-dep
        //     versions from the resolver.
        if let Err(e) =
            finalize_packages_in_manifest(&staged, &direct_versions, save_flags, save_config)
        {
            last_err = Some(e);
            break;
        }
    }

    if let Some(e) = last_err {
        // Drop `tx` here without committing → every snapshotted manifest
        // is restored to its pre-stage bytes.
        return Err(e);
    }

    // All members succeeded — persist every staged + finalized manifest.
    tx.commit();
    Ok(())
}

/// Install a Swift package via SE-0292 registry: edit Package.swift + resolve.
async fn run_swift_install(
    project_dir: &Path,
    name: &lpm_common::PackageName,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
    json_output: bool,
    registry_url: &str,
) -> Result<(), LpmError> {
    use crate::swift_manifest;
    use crate::xcode_project;

    let se0292_id = swift_manifest::lpm_to_se0292_id(name);
    let product_name = ver_meta.swift_product_name().unwrap_or_else(|| &name.name);

    // Detect project type: SPM (Package.swift) vs Xcode (.xcodeproj)
    let manifest_path = swift_manifest::find_package_swift(project_dir);
    let xcodeproj_path = xcode_project::find_xcodeproj(project_dir);

    match (manifest_path, xcodeproj_path) {
        // Both exist or only SPM → use existing SPM flow
        (Some(manifest), _) => {
            run_swift_install_spm(
                project_dir,
                &manifest,
                name,
                version,
                ver_meta,
                &se0292_id,
                product_name,
                json_output,
                registry_url,
            )
            .await
        }
        // Only Xcode project → new Xcode wrapper flow
        (None, Some(xcodeproj)) => {
            run_swift_install_xcode(
                project_dir,
                &xcodeproj,
                name,
                version,
                ver_meta,
                &se0292_id,
                product_name,
                json_output,
                registry_url,
            )
            .await
        }
        // Neither
        (None, None) => Err(LpmError::Registry(
            "No Package.swift or .xcodeproj found. Initialize a Swift project first.".into(),
        )),
    }
}

/// Install a Swift package into an SPM project.
#[allow(clippy::too_many_arguments)]
async fn run_swift_install_spm(
    project_dir: &Path,
    manifest_path: &Path,
    name: &lpm_common::PackageName,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
    se0292_id: &str,
    product_name: &str,
    json_output: bool,
    registry_url: &str,
) -> Result<(), LpmError> {
    use crate::swift_manifest;

    let manifest_dir = manifest_path.parent().unwrap_or(project_dir);

    if !json_output {
        output::info(&format!(
            "Installing {} via SE-0292 registry → {}",
            name.scoped().bold(),
            se0292_id.dimmed(),
        ));
    }

    // Detect targets
    let targets = swift_manifest::get_spm_targets(manifest_dir).unwrap_or_default();
    let target_name = if targets.len() == 1 {
        targets[0].clone()
    } else if targets.len() > 1 {
        let mut sel = cliclack::select("Which target should use this dependency?");
        for (i, target) in targets.iter().enumerate() {
            sel = sel.item(target.clone(), target, "");
            if i == 0 {
                sel = sel.initial_value(target.clone());
            }
        }
        sel.interact()
            .map_err(|e| LpmError::Registry(format!("prompt failed: {e}")))?
    } else {
        return Err(LpmError::Registry(
            "No non-test targets found in Package.swift.".into(),
        ));
    };

    // Edit Package.swift
    let edit = swift_manifest::add_registry_dependency(
        manifest_path,
        se0292_id,
        version,
        product_name,
        &target_name,
    )?;

    if edit.already_exists {
        if !json_output {
            output::info(&format!(
                "{} is already in Package.swift",
                se0292_id.dimmed()
            ));
        }
    } else if !json_output {
        output::success(&format!(
            "Added .package(id: \"{}\", from: \"{}\")",
            se0292_id, version
        ));
        output::success(&format!(
            "Added .product(name: \"{}\") to target {}",
            product_name,
            target_name.bold()
        ));
    }

    // Resolve
    if !edit.already_exists {
        // Auto-configure registry scope if needed
        crate::commands::swift_registry::ensure_configured(registry_url, manifest_dir, json_output)
            .await?;

        if !json_output {
            output::info("Resolving Swift packages...");
        }
        swift_manifest::run_swift_resolve(manifest_dir)?;
    }

    // Output
    if json_output {
        let json = serde_json::json!({
            "package": name.scoped(),
            "version": version,
            "mode": "registry",
            "se0292_id": se0292_id,
            "product_name": product_name,
            "target": target_name,
            "already_existed": edit.already_exists,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if !edit.already_exists {
        println!();
        output::success(&format!(
            "Installed {}@{} via SE-0292 registry",
            name.scoped().bold(),
            version,
        ));
        println!("  import {} // in your Swift code", product_name.bold());
    }

    // Security check
    if ver_meta.has_security_issues() && !json_output {
        crate::commands::add::print_security_warnings(&name.scoped(), version, ver_meta);
    }

    if !json_output && !edit.already_exists {
        println!();
    }

    Ok(())
}

/// Install a Swift package into an Xcode app project via local wrapper package.
#[allow(clippy::too_many_arguments)]
async fn run_swift_install_xcode(
    project_dir: &Path,
    xcodeproj_path: &Path,
    name: &lpm_common::PackageName,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
    se0292_id: &str,
    product_name: &str,
    json_output: bool,
    registry_url: &str,
) -> Result<(), LpmError> {
    use crate::swift_manifest;
    use crate::xcode_project;

    // Resolve the project root (xcodeproj's parent)
    let project_root = xcodeproj_path.parent().unwrap_or(project_dir);

    if !json_output {
        output::info(&format!(
            "Installing {} via SE-0292 registry → {} (Xcode project)",
            name.scoped().bold(),
            se0292_id.dimmed(),
        ));
    }

    // Step 1: Ensure LPMDependencies wrapper package exists
    let wrapper = swift_manifest::ensure_wrapper_package(project_root)?;
    if wrapper.created && !json_output {
        output::success("Created Packages/LPMDependencies/ wrapper package");
    }

    // Step 2: Add the registry dependency to the wrapper Package.swift
    let edit = swift_manifest::add_wrapper_dependency(
        &wrapper.manifest_path,
        se0292_id,
        version,
        product_name,
    )?;

    if edit.already_exists {
        if !json_output {
            output::info(&format!("{} is already installed", se0292_id.dimmed()));
        }
    } else if !json_output {
        output::success(&format!(
            "Added .package(id: \"{}\", from: \"{}\")",
            se0292_id, version,
        ));
    }

    // Step 3: Link to Xcode project (pbxproj editing — first install only)
    let link_result = xcode_project::link_local_package(
        xcodeproj_path,
        swift_manifest::LPM_DEPS_PACKAGE_NAME,
        swift_manifest::LPM_DEPS_REL_PATH,
    )?;

    if link_result.package_ref_added && !json_output {
        output::success(&format!(
            "Linked LPMDependencies to Xcode target {}",
            link_result.target_name.bold(),
        ));
    }

    // Step 4: Resolve Swift packages
    if !edit.already_exists {
        // Auto-configure registry scope if needed
        let wrapper_dir = wrapper.manifest_path.parent().unwrap_or(project_root);
        crate::commands::swift_registry::ensure_configured(registry_url, wrapper_dir, json_output)
            .await?;

        if !json_output {
            output::info("Resolving Swift packages...");
        }
        swift_manifest::run_swift_resolve(wrapper_dir)?;
    }

    // Step 5: Output
    if json_output {
        let json = serde_json::json!({
            "package": name.scoped(),
            "version": version,
            "mode": "registry",
            "project_type": "xcode",
            "se0292_id": se0292_id,
            "product_name": product_name,
            "wrapper_package": "Packages/LPMDependencies",
            "xcode_target": link_result.target_name,
            "already_existed": edit.already_exists,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if !edit.already_exists {
        println!();
        output::success(&format!(
            "Installed {}@{} via SE-0292 registry",
            name.scoped().bold(),
            version,
        ));
        println!("  import {} // in your Swift code", product_name.bold());
    }

    // Security check
    if ver_meta.has_security_issues() && !json_output {
        crate::commands::add::print_security_warnings(&name.scoped(), version, ver_meta);
    }

    // Xcode warning (first link only)
    if link_result.package_ref_added && !json_output {
        println!();
        output::warn("If Xcode is open, close and reopen the project to pick up changes.");
    }

    if !json_output && !edit.already_exists {
        println!();
    }

    Ok(())
}

// Phase 33: the legacy `parse_package_spec` was deleted. Its replacement
// is `crate::save_spec::parse_user_save_intent`, which returns a strongly
// typed `UserSaveIntent` instead of `(String, String)`. The Swift routing
// site in `run_add_packages` calls `intent_to_range_string` directly to get
// a range string for metadata fetching.
//
// See `crate::save_spec` for the parser tests; the old in-file
// `parse_spec_*` tests were superseded by `save_spec::tests::parse_*`
// which cover the same matrix without the legacy `*`-default behavior.

/// Render a [`UserSaveIntent`] back to a string range for the legacy
/// metadata-fetch path. Used at the Swift ecosystem routing site only;
/// the manifest-write path uses [`SaveSpecDecision`] directly.
fn intent_to_range_string(intent: &crate::save_spec::UserSaveIntent) -> String {
    use crate::save_spec::UserSaveIntent;
    match intent {
        UserSaveIntent::Bare | UserSaveIntent::Wildcard => "*".to_string(),
        UserSaveIntent::Exact(s)
        | UserSaveIntent::Range(s)
        | UserSaveIntent::DistTag(s)
        | UserSaveIntent::Workspace(s) => s.clone(),
    }
}

/// Resolve the user-specified version range against a package's available versions.
///
/// When the user specifies a version (e.g., `@1.0.0` or `@^2.0.0`), find the best
/// matching version from metadata. When no version is specified (`*`), fall back to
/// `latest_ver`.
///
/// Returns the resolved version string.
fn resolve_version_from_spec<'a>(
    range_spec: &str,
    metadata: &'a lpm_registry::PackageMetadata,
    latest_ver: &'a str,
) -> Result<&'a str, LpmError> {
    // If no version specified (wildcard), use latest
    if range_spec == "*" {
        return Ok(latest_ver);
    }

    let range = lpm_semver::VersionReq::parse(range_spec).map_err(|_| {
        LpmError::InvalidVersionRange(format!("invalid version range: {range_spec}"))
    })?;

    // Parse all available versions and find the best match
    let mut parsed_versions: Vec<(lpm_semver::Version, &str)> = metadata
        .versions
        .keys()
        .filter_map(|v_str| {
            lpm_semver::Version::parse(v_str)
                .ok()
                .map(|v| (v, v_str.as_str()))
        })
        .collect();

    // Sort so max_satisfying-style logic works
    parsed_versions.sort_by(|a, b| a.0.cmp(&b.0));

    // Find the highest version satisfying the range
    let best = parsed_versions.iter().rev().find(|(v, _)| range.matches(v));

    match best {
        Some((_, ver_str)) => Ok(ver_str),
        None => Err(LpmError::NotFound(format!(
            "no version matching {range_spec} found (available: {})",
            metadata
                .versions
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn make_spinner(msg: &str) -> cliclack::ProgressBar {
    let spinner = cliclack::spinner();
    spinner.start(msg);
    spinner
}

/// Auto-install agent skills for direct LPM packages.
///
/// For each direct LPM dependency, fetches its skills from the registry and
/// writes them to `.lpm/skills/{owner.package}/`. Also ensures `.gitignore`
/// includes the skills directory and triggers editor auto-integration.
async fn install_skills_for_packages(
    client: &Arc<RegistryClient>,
    packages: &[String],
    project_dir: &Path,
    no_editor_setup: bool,
) {
    // Fetch all package skills in parallel
    let futures: Vec<_> = packages
        .iter()
        .map(|pkg_name| {
            let client = client.clone();
            let pkg = pkg_name.clone();
            async move {
                let short_name = pkg.strip_prefix("@lpm.dev/").unwrap_or(&pkg).to_string();
                let result = client.get_skills(&short_name, None).await;
                (short_name, result)
            }
        })
        .collect();

    let results = futures::future::join_all(futures).await;

    let mut total_installed = 0;

    for (short_name, result) in results {
        match result {
            Ok(response) if !response.skills.is_empty() => {
                let skills_dir = project_dir.join(".lpm").join("skills").join(&short_name);
                let _ = std::fs::create_dir_all(&skills_dir);

                for skill in &response.skills {
                    if !lpm_common::is_safe_skill_name(&skill.name) {
                        tracing::warn!("skipping skill with unsafe name: {}", skill.name);
                        continue;
                    }

                    let content = skill
                        .raw_content
                        .as_deref()
                        .or(skill.content.as_deref())
                        .unwrap_or("");
                    if !content.is_empty() {
                        let path = skills_dir.join(format!("{}.md", skill.name));
                        let _ = std::fs::write(&path, content);
                        total_installed += 1;
                    }
                }
            }
            _ => {} // No skills or API error — skip silently
        }
    }

    if total_installed > 0 {
        output::info(&format!("Installed {total_installed} agent skill(s)"));

        // Ensure .gitignore includes .lpm/skills/
        ensure_skills_gitignore(project_dir);

        // Auto-integrate with editors (respects --no-editor-setup)
        if !no_editor_setup {
            let integrations = crate::editor_skills::auto_integrate_skills(project_dir);
            for msg in &integrations {
                output::info(msg);
            }
        }
    }
}

/// Ensure `.gitignore` contains an entry for `.lpm/skills/`.
pub fn ensure_skills_gitignore(project_dir: &Path) {
    let gitignore_path = project_dir.join(".gitignore");
    let marker = ".lpm/skills/";

    if gitignore_path.exists() {
        let content = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        if content.lines().any(|l| l.trim() == marker) {
            return; // Already present
        }
        // Append using OpenOptions to reduce TOCTOU window vs read-then-write
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .open(&gitignore_path)
        {
            if !content.ends_with('\n') {
                let _ = writeln!(file);
            }
            let _ = writeln!(file);
            let _ = writeln!(file, "# LPM Agent Skills (auto-generated)");
            let _ = writeln!(file, "{marker}");
        }
    } else {
        let _ = std::fs::write(&gitignore_path, format!("# LPM Agent Skills\n{marker}\n"));
    }
}

// Phase 46 P1: `read_auto_build_config` was removed as part of
// consolidating script-config reads into
// `crate::script_policy_config::ScriptPolicyConfig`. Callers now
// access `.auto_build` on the loader's return value. Equivalent test
// coverage lives in `script_policy_config::tests`.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn confirm_prompt_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[cfg(unix)]
    struct StdinSwapGuard {
        original_stdin_fd: std::os::fd::RawFd,
    }

    #[cfg(unix)]
    impl StdinSwapGuard {
        fn replace_with(new_stdin_fd: std::os::fd::RawFd) -> Self {
            let original_stdin_fd = unsafe { libc::dup(libc::STDIN_FILENO) };
            assert!(
                original_stdin_fd >= 0,
                "failed to duplicate stdin before PTY swap"
            );

            let swap_result = unsafe { libc::dup2(new_stdin_fd, libc::STDIN_FILENO) };
            assert!(swap_result >= 0, "failed to swap stdin to PTY slave");

            Self { original_stdin_fd }
        }
    }

    #[cfg(unix)]
    impl Drop for StdinSwapGuard {
        fn drop(&mut self) {
            let _ = unsafe { libc::dup2(self.original_stdin_fd, libc::STDIN_FILENO) };
            let _ = unsafe { libc::close(self.original_stdin_fd) };
        }
    }

    #[cfg(unix)]
    fn with_tty_stdin_input<F, R>(input: &str, action: F) -> R
    where
        F: FnOnce() -> R,
    {
        use std::fs::File;
        use std::io::Write;
        use std::os::fd::FromRawFd;

        let _lock = confirm_prompt_test_lock();

        let mut master_fd = -1;
        let mut slave_fd = -1;
        let open_result = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(open_result, 0, "failed to create PTY pair for prompt test");

        let stdin_guard = StdinSwapGuard::replace_with(slave_fd);
        let _ = unsafe { libc::close(slave_fd) };

        let mut master = unsafe { File::from_raw_fd(master_fd) };
        master
            .write_all(input.as_bytes())
            .expect("failed to feed PTY input");
        master.flush().expect("failed to flush PTY input");

        let result = action();

        drop(master);
        drop(stdin_guard);

        result
    }

    #[test]
    fn auto_build_trigger_enables_when_any_current_source_requests_it() {
        assert!(should_auto_build(true, false, false));
        assert!(should_auto_build(false, true, false));
        assert!(should_auto_build(false, false, true));
        assert!(!should_auto_build(false, false, false));
    }

    // Phase 46 P1: the two `read_auto_build_config_*` tests were
    // removed alongside the ad-hoc helper. Equivalent coverage lives
    // in `script_policy_config::tests::from_package_json_reads_all_four_keys`
    // and `::from_package_json_missing_file_returns_defaults` and
    // `::from_package_json_malformed_json_returns_defaults`.

    /// Build a PackageMetadata with the given version strings and latest tag.
    fn make_metadata(versions: &[&str], latest: &str) -> lpm_registry::PackageMetadata {
        let mut version_map = std::collections::HashMap::new();
        for &v in versions {
            version_map.insert(
                v.to_string(),
                lpm_registry::VersionMetadata {
                    name: "@lpm.dev/acme.swift-logger".to_string(),
                    version: v.to_string(),
                    description: None,
                    dependencies: Default::default(),
                    dev_dependencies: Default::default(),
                    peer_dependencies: Default::default(),
                    optional_dependencies: Default::default(),
                    os: vec![],
                    cpu: vec![],
                    dist: None,
                    readme: None,
                    lpm_config: None,
                    ecosystem: Some("swift".to_string()),
                    swift_meta: None,
                    behavioral_tags: None,
                    lifecycle_scripts: None,
                    security_findings: None,
                    quality_score: None,
                    vulnerabilities: None,
                },
            );
        }

        let mut dist_tags = std::collections::HashMap::new();
        dist_tags.insert("latest".to_string(), latest.to_string());

        lpm_registry::PackageMetadata {
            name: "@lpm.dev/acme.swift-logger".to_string(),
            description: None,
            dist_tags,
            versions: version_map,
            time: Default::default(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: Some(latest.to_string()),
            ecosystem: Some("swift".to_string()),
        }
    }

    // ── parse_package_spec ──────────────────────────────────────────
    //
    // The legacy `parse_package_spec` function and its tests were removed
    // in Phase 33. The replacement parser is `save_spec::parse_user_save_intent`,
    // which returns a strongly typed `UserSaveIntent` enum and is exhaustively
    // tested in `save_spec::tests::parse_*` (15 cases covering scoped,
    // unscoped, exact, range, dist-tag, wildcard, and workspace inputs).
    // Re-asserting parser behavior here would just duplicate that coverage.

    // ── resolve_version_from_spec ───────────────────────────────────

    #[test]
    fn resolve_wildcard_returns_latest() {
        let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");
        let result = resolve_version_from_spec("*", &meta, "3.0.0").unwrap();
        assert_eq!(result, "3.0.0");
    }

    #[test]
    fn resolve_exact_version_returns_that_version() {
        let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");
        let result = resolve_version_from_spec("1.0.0", &meta, "3.0.0").unwrap();
        assert_eq!(result, "1.0.0");
    }

    #[test]
    fn resolve_caret_range_returns_best_match() {
        let meta = make_metadata(&["1.0.0", "1.5.0", "2.0.0", "2.1.0"], "2.1.0");
        let result = resolve_version_from_spec("^1.0.0", &meta, "2.1.0").unwrap();
        assert_eq!(result, "1.5.0");
    }

    #[test]
    fn resolve_tilde_range_returns_best_match() {
        let meta = make_metadata(&["1.0.0", "1.0.5", "1.1.0", "2.0.0"], "2.0.0");
        let result = resolve_version_from_spec("~1.0.0", &meta, "2.0.0").unwrap();
        assert_eq!(result, "1.0.5");
    }

    #[test]
    fn resolve_no_match_returns_error() {
        let meta = make_metadata(&["1.0.0", "1.5.0"], "1.5.0");
        let result = resolve_version_from_spec("^3.0.0", &meta, "1.5.0");
        assert!(result.is_err());
    }

    /// This is the exact bug scenario: user specifies `@1.0.0` but the code
    /// previously ignored it and used `latest_ver` (3.0.0) instead.
    #[test]
    fn bug_version_spec_not_ignored_for_swift_packages() {
        let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");

        // User asked for @1.0.0 — must get 1.0.0, NOT 3.0.0
        let result = resolve_version_from_spec("1.0.0", &meta, "3.0.0").unwrap();
        assert_eq!(
            result, "1.0.0",
            "user-specified version @1.0.0 should be respected, not silently replaced with latest"
        );

        // User asked for @^2.0.0 — must get 2.0.0, NOT 3.0.0
        let result = resolve_version_from_spec("^2.0.0", &meta, "3.0.0").unwrap();
        assert_eq!(
            result, "2.0.0",
            "user-specified range @^2.0.0 should resolve to 2.0.0, not latest"
        );
    }

    #[test]
    fn ensure_skills_gitignore_appends_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

        ensure_skills_gitignore(dir.path());

        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(content.contains(".lpm/skills/"), "entry should be added");
        assert!(
            content.contains("node_modules/"),
            "existing content preserved"
        );
    }

    #[test]
    fn ensure_skills_gitignore_no_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

        ensure_skills_gitignore(dir.path());
        ensure_skills_gitignore(dir.path());

        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        let count = content.matches(".lpm/skills/").count();
        assert_eq!(count, 1, "should not duplicate entry");
    }

    // ── install state (Phase 34.1: delegated to crate::install_state) ──

    /// Set up a tempdir that looks like a post-install project:
    /// package.json, lpm.lock, node_modules/, .lpm/install-hash.
    fn setup_installed_project(dir: &std::path::Path) {
        let pkg = r#"{"name":"test","dependencies":{"lodash":"^4.0.0"}}"#;
        let lock = "[packages]\nname = \"lodash\"\nversion = \"4.17.21\"\n";

        std::fs::write(dir.join("package.json"), pkg).unwrap();
        std::fs::write(dir.join("lpm.lock"), lock).unwrap();
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();

        let hash = crate::install_state::compute_install_hash(pkg, lock);
        std::fs::create_dir_all(dir.join(".lpm")).unwrap();
        std::fs::write(dir.join(".lpm").join("install-hash"), &hash).unwrap();
    }

    #[test]
    fn fast_exit_when_everything_matches() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        assert!(
            crate::install_state::check_install_state(dir.path()).up_to_date,
            "should be up to date when hash matches and node_modules is clean"
        );
    }

    #[test]
    fn fast_exit_fails_when_package_json_changed() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        // Simulate adding a new dependency
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"test","dependencies":{"lodash":"^4.0.0","express":"^4.0.0"}}"#,
        )
        .unwrap();

        assert!(
            !crate::install_state::check_install_state(dir.path()).up_to_date,
            "should NOT be up to date when package.json changed"
        );
    }

    #[test]
    fn fast_exit_fails_when_lockfile_changed() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        // Simulate lockfile update
        std::fs::write(
            dir.path().join("lpm.lock"),
            "[packages]\nname = \"lodash\"\nversion = \"4.17.22\"\n",
        )
        .unwrap();

        assert!(
            !crate::install_state::check_install_state(dir.path()).up_to_date,
            "should NOT be up to date when lockfile changed"
        );
    }

    #[test]
    fn fast_exit_fails_when_no_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());
        std::fs::remove_file(dir.path().join("lpm.lock")).unwrap();

        assert!(
            !crate::install_state::check_install_state(dir.path()).up_to_date,
            "should NOT be up to date when lockfile is missing"
        );
    }

    #[test]
    fn fast_exit_fails_when_no_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());
        std::fs::remove_dir_all(dir.path().join("node_modules")).unwrap();

        assert!(
            !crate::install_state::check_install_state(dir.path()).up_to_date,
            "should NOT be up to date when node_modules is missing"
        );
    }

    #[test]
    fn fast_exit_fails_when_no_hash_file() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());
        std::fs::remove_file(dir.path().join(".lpm").join("install-hash")).unwrap();

        assert!(
            !crate::install_state::check_install_state(dir.path()).up_to_date,
            "should NOT be up to date when install-hash is missing"
        );
    }

    #[test]
    fn fast_exit_fails_when_node_modules_modified() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        // Touch node_modules AFTER the hash was written — simulates
        // external modification (user deleted a package folder, etc.)
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::create_dir_all(dir.path().join("node_modules").join("new-pkg")).unwrap();

        assert!(
            !crate::install_state::check_install_state(dir.path()).up_to_date,
            "should NOT be up to date when node_modules was modified after hash"
        );
    }

    #[test]
    fn fast_exit_on_empty_project() {
        let dir = tempfile::tempdir().unwrap();
        // Completely empty directory — no package.json at all
        assert!(
            !crate::install_state::check_install_state(dir.path()).up_to_date,
            "should NOT be up to date on empty directory"
        );
    }

    /// Verify that --force is defined as a CLI flag on the Install command.
    /// This is a structural test — ensures the flag doesn't get accidentally removed.
    #[test]
    fn force_flag_defined_in_cli() {
        use clap::Parser;

        // Parse with --force — should succeed
        let result = crate::Cli::try_parse_from(["lpm", "install", "--force"]);
        assert!(
            result.is_ok(),
            "lpm install --force should be a valid command: {:?}",
            result.err()
        );
    }

    /// Verify that --force can be combined with other install flags.
    #[test]
    fn force_flag_combines_with_other_flags() {
        use clap::Parser;

        let result =
            crate::Cli::try_parse_from(["lpm", "install", "--force", "--offline", "--allow-new"]);
        assert!(
            result.is_ok(),
            "lpm install --force --offline --allow-new should parse: {:?}",
            result.err()
        );
    }

    /// Verify check_install_state returns up_to_date for a properly set up project,
    /// confirming that --force's bypass of this check is meaningful.
    #[test]
    fn force_bypass_is_meaningful() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        // Without --force, this returns true (fast exit)
        assert!(
            crate::install_state::check_install_state(dir.path()).up_to_date,
            "project should be up-to-date — --force bypasses this"
        );

        // With --force, the guard `!force && ... && install_state.up_to_date`
        // short-circuits, so the check result is ignored.
        // We can't test the full pipeline here (needs registry), but we
        // verify that the bypass target exists and returns true.
    }

    // ── Phase 33: stage_packages_to_manifest behavior ─────────────────────
    //
    // These tests cover the stage step in isolation (no install pipeline,
    // no transaction guard). The Phase 33 contract for stage:
    //
    //   - Explicit Exact/Range/Wildcard/Workspace user input → write
    //     verbatim, mark `StagedKind::Final`.
    //   - Bare reinstall of an existing dep with no rewrite-forcing flag →
    //     do not touch the manifest, mark `StagedKind::Skipped` (no churn).
    //   - Bare or dist-tag for a new dep, OR existing dep with a flag →
    //     write `STAGE_PLACEHOLDER` ("*"), mark `StagedKind::Placeholder`.
    //     The placeholder is replaced by `finalize_packages_in_manifest`
    //     once the resolver returns the concrete version.
    //
    // The end-to-end smoke (placeholder → final spec) is exercised by the
    // workflow tests in `tests/workflows/tests/install.rs`; these unit
    // tests are the per-branch coverage for the stage logic.

    fn write_manifest(path: &Path, value: &serde_json::Value) {
        std::fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    }

    fn read_manifest(path: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn stage_explicit_exact_writes_to_dependencies_when_save_dev_false() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        let staged = stage_packages_to_manifest(
            &pkg_path,
            &["react@18.2.0".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        let after = read_manifest(&pkg_path);
        assert_eq!(after["dependencies"]["react"], "18.2.0");
        assert!(after.get("devDependencies").is_none());
        assert_eq!(staged.entries.len(), 1);
        assert!(matches!(staged.entries[0].kind, StagedKind::Final));
        assert!(!staged.has_placeholders());
    }

    #[test]
    fn stage_explicit_exact_writes_to_dev_dependencies_when_save_dev_true() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        let staged = stage_packages_to_manifest(
            &pkg_path,
            &["vitest@1.0.0".to_string()],
            true,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        let after = read_manifest(&pkg_path);
        assert_eq!(after["devDependencies"]["vitest"], "1.0.0");
        assert!(after.get("dependencies").is_none());
        assert!(matches!(staged.entries[0].kind, StagedKind::Final));
    }

    #[test]
    fn stage_preserves_existing_unrelated_entries() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(
            &pkg_path,
            &serde_json::json!({
                "name": "demo",
                "version": "1.0.0",
                "scripts": {"build": "tsup"},
                "dependencies": {"existing": "1.0.0"},
                "lpm": {"trustedDependencies": ["esbuild"]},
            }),
        );

        // Bare new dep → placeholder.
        let staged = stage_packages_to_manifest(
            &pkg_path,
            &["new-pkg".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        let after = read_manifest(&pkg_path);
        assert_eq!(after["name"], "demo");
        assert_eq!(after["version"], "1.0.0");
        assert_eq!(after["scripts"]["build"], "tsup");
        assert_eq!(after["dependencies"]["existing"], "1.0.0");
        // Bare staging → placeholder, not the legacy `*` final write.
        assert_eq!(after["dependencies"]["new-pkg"], STAGE_PLACEHOLDER);
        assert_eq!(after["lpm"]["trustedDependencies"][0], "esbuild");
        assert!(matches!(staged.entries[0].kind, StagedKind::Placeholder));
        assert!(staged.has_placeholders());
    }

    #[test]
    fn stage_handles_mixed_explicit_and_bare_specs() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        let staged = stage_packages_to_manifest(
            &pkg_path,
            &[
                "react@18.2.0".to_string(),
                "lodash@^4.17.0".to_string(),
                "no-version-spec".to_string(),
            ],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        let after = read_manifest(&pkg_path);
        // Explicit Exact + Range → preserved verbatim.
        assert_eq!(after["dependencies"]["react"], "18.2.0");
        assert_eq!(after["dependencies"]["lodash"], "^4.17.0");
        // Bare → placeholder (NOT the legacy `*` final write — finalize
        // would replace this with `^<resolved>`).
        assert_eq!(after["dependencies"]["no-version-spec"], STAGE_PLACEHOLDER);

        assert_eq!(staged.entries.len(), 3);
        assert!(matches!(staged.entries[0].kind, StagedKind::Final));
        assert!(matches!(staged.entries[1].kind, StagedKind::Final));
        assert!(matches!(staged.entries[2].kind, StagedKind::Placeholder));
    }

    #[test]
    fn stage_explicit_spec_overwrites_existing_entry_with_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(
            &pkg_path,
            &serde_json::json!({
                "name": "demo",
                "dependencies": {"react": "17.0.0"},
            }),
        );

        // Explicit user spec → always rewrites, even when an entry exists.
        let staged = stage_packages_to_manifest(
            &pkg_path,
            &["react@18.2.0".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        let after = read_manifest(&pkg_path);
        assert_eq!(after["dependencies"]["react"], "18.2.0");
        assert!(matches!(staged.entries[0].kind, StagedKind::Final));
    }

    /// Phase 33 row 12 (no churn): bare reinstall of an existing dep, no
    /// rewrite-forcing flag → manifest is NOT touched, entry is Skipped.
    #[test]
    fn stage_bare_reinstall_of_existing_dep_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(
            &pkg_path,
            &serde_json::json!({
                "name": "demo",
                "dependencies": {"ms": "~2.1.3"},
            }),
        );

        let pre_bytes = std::fs::read(&pkg_path).unwrap();

        let staged = stage_packages_to_manifest(
            &pkg_path,
            &["ms".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        let post_bytes = std::fs::read(&pkg_path).unwrap();
        // The entry stays exactly as-is.
        assert_eq!(
            post_bytes, pre_bytes,
            "no-churn rule: bare reinstall of an existing dep must not rewrite the manifest"
        );
        let after = read_manifest(&pkg_path);
        assert_eq!(after["dependencies"]["ms"], "~2.1.3");
        assert!(matches!(staged.entries[0].kind, StagedKind::Skipped));
        assert!(!staged.has_placeholders());
    }

    /// **Phase 33 audit Finding 3 regression.** A dist-tag install
    /// against an existing dep is NOT a "bare reinstall" — the user typed
    /// `@latest`/`@beta`/`@next`, which is explicit input asking for the
    /// current value of that tag. Stage MUST stage a placeholder so
    /// finalize can rewrite the manifest with the resolved version.
    ///
    /// Pre-fix: `lpm install react@latest` on an existing `react: "17.0.0"`
    /// entry would hit the Skipped branch and never update the manifest,
    /// even though the resolver picked a new version.
    #[test]
    fn stage_dist_tag_on_existing_dep_writes_placeholder_not_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(
            &pkg_path,
            &serde_json::json!({
                "name": "demo",
                "dependencies": {"react": "17.0.0"},
            }),
        );

        let staged = stage_packages_to_manifest(
            &pkg_path,
            &["react@latest".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        let after = read_manifest(&pkg_path);
        assert_eq!(
            after["dependencies"]["react"], STAGE_PLACEHOLDER,
            "dist-tag against existing dep must stage a placeholder, not skip — \
             the user explicitly asked for a new resolution under that tag"
        );
        assert!(
            matches!(staged.entries[0].kind, StagedKind::Placeholder),
            "dist-tag intent must produce StagedKind::Placeholder, not Skipped; \
             got: {:?}",
            staged.entries[0].kind
        );
    }

    /// Phase 33: bare reinstall of an existing dep WITH a rewrite-forcing
    /// flag → write a placeholder, finalize will replace with the new
    /// resolved-version-derived spec. This is the `--exact` opt-in path.
    #[test]
    fn stage_bare_reinstall_with_exact_flag_writes_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(
            &pkg_path,
            &serde_json::json!({
                "name": "demo",
                "dependencies": {"ms": "~2.1.3"},
            }),
        );

        let flags = crate::save_spec::SaveFlags {
            exact: true,
            ..Default::default()
        };
        let staged =
            stage_packages_to_manifest(&pkg_path, &["ms".to_string()], false, flags, true).unwrap();

        let after = read_manifest(&pkg_path);
        // Existing entry was overwritten with the placeholder; finalize
        // would then replace it with the resolved exact version.
        assert_eq!(after["dependencies"]["ms"], STAGE_PLACEHOLDER);
        assert!(matches!(staged.entries[0].kind, StagedKind::Placeholder));
    }

    #[test]
    fn stage_errors_when_manifest_missing() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("does-not-exist").join("package.json");

        let result = stage_packages_to_manifest(
            &absent,
            &["foo".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        );

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no package.json"));
    }

    #[test]
    fn stage_errors_on_malformed_input_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        std::fs::write(&pkg_path, "{not valid json").unwrap();
        let original = std::fs::read_to_string(&pkg_path).unwrap();

        let result = stage_packages_to_manifest(
            &pkg_path,
            &["foo".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        );

        assert!(result.is_err(), "malformed manifest must error");
        // The corrupt file must be left unchanged.
        assert_eq!(std::fs::read_to_string(&pkg_path).unwrap(), original);
    }

    #[test]
    fn stage_writes_atomic_pretty_json_with_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        stage_packages_to_manifest(
            &pkg_path,
            &["foo".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        let raw = std::fs::read_to_string(&pkg_path).unwrap();
        // Pretty-printed with indentation.
        assert!(raw.contains("  \"dependencies\""));
        // Trailing newline.
        assert!(raw.ends_with('\n'));
    }

    // ── Phase 33: finalize_packages_in_manifest behavior ──────────────────

    /// Helper: build a `name → Version` map from `(name, version_str)` pairs.
    fn make_resolved(pairs: &[(&str, &str)]) -> HashMap<String, lpm_semver::Version> {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_string(), lpm_semver::Version::parse(v).unwrap()))
            .collect()
    }

    /// Phase 33 end-to-end (stage → finalize): bare install of a fresh dep
    /// gets a placeholder at stage, then `^<resolved>` after finalize.
    #[test]
    fn finalize_bare_replaces_placeholder_with_caret_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        let staged = stage_packages_to_manifest(
            &pkg_path,
            &["ms".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();
        // Sanity: stage left a placeholder.
        assert_eq!(
            read_manifest(&pkg_path)["dependencies"]["ms"],
            STAGE_PLACEHOLDER
        );

        let resolved = make_resolved(&[("ms", "2.1.3")]);
        finalize_packages_in_manifest(
            &staged,
            &resolved,
            crate::save_spec::SaveFlags::default(),
            crate::save_spec::SaveConfig::default(),
        )
        .unwrap();

        let after = read_manifest(&pkg_path);
        assert_eq!(
            after["dependencies"]["ms"], "^2.1.3",
            "finalize must replace `*` placeholder with `^<resolved>`"
        );
    }

    /// Finalize is a no-op when no entries are placeholders.
    #[test]
    fn finalize_is_noop_when_no_placeholders() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        // Stage explicit-only specs → no placeholders.
        let staged = stage_packages_to_manifest(
            &pkg_path,
            &["react@18.2.0".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();
        let pre = std::fs::read_to_string(&pkg_path).unwrap();

        finalize_packages_in_manifest(
            &staged,
            &HashMap::new(),
            crate::save_spec::SaveFlags::default(),
            crate::save_spec::SaveConfig::default(),
        )
        .unwrap();

        // Manifest is byte-identical — finalize never opened the file.
        let post = std::fs::read_to_string(&pkg_path).unwrap();
        assert_eq!(pre, post);
    }

    // ── Phase 33 audit Finding 1 regression ──────────────────────────────
    //
    // `collect_direct_versions` is the audit-aligned replacement for the
    // pre-fix `collect_resolved_versions_from_lockfile`. The pre-fix code
    // did a flat name scan over the lockfile, which would pick the wrong
    // version (transitive instead of direct) if the lockfile ever had
    // multiple entries for the same name. The fix uses the resolver's
    // `is_direct: bool` flag, which is set per `InstallPackage` based on
    // membership in the staged manifest's `dependencies` map — so the
    // direct/transitive distinction is unambiguous.
    //
    // These tests build hand-crafted `Vec<InstallPackage>` fixtures that
    // include both direct AND transitive entries for the same name, then
    // assert that the helper picks ONLY the direct entry. This is the
    // load-bearing correctness test for Finding 1.

    /// Helper to construct an `InstallPackage` with the fields the
    /// `collect_direct_versions` helper actually reads. Other fields are
    /// stubbed because they don't affect the result.
    fn fake_pkg(name: &str, version: &str, is_direct: bool) -> InstallPackage {
        InstallPackage {
            name: name.to_string(),
            version: version.to_string(),
            source: "registry+https://registry.npmjs.org".to_string(),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            root_link_names: None,
            is_direct,
            is_lpm: false,
            integrity: None,
            tarball_url: None,
        }
    }

    /// Finding 1 the audit cared about: when the same package name has
    /// BOTH a direct entry and a transitive entry at different versions,
    /// the helper must pick the DIRECT version, regardless of input order.
    #[test]
    fn collect_direct_versions_picks_direct_over_transitive_same_name() {
        let packages = vec![
            // Transitive `ms@1.5.0` first (e.g., from a legacy-pkg
            // depending on ms@~1.5.0).
            fake_pkg("ms", "1.5.0", false),
            // Direct `ms@2.1.3` second (the user's `lpm install ms`).
            fake_pkg("ms", "2.1.3", true),
            // Unrelated direct dep.
            fake_pkg("legacy-pkg", "1.0.0", true),
        ];

        let map = collect_direct_versions(&packages);

        // The pre-fix flat name scan would have last-write-wins on `ms`,
        // so the result depends on iteration order. Post-fix, only the
        // direct entry is considered, and there's exactly one.
        assert_eq!(
            map.get("ms").map(|v| v.to_string()),
            Some("2.1.3".to_string()),
            "Finding 1: collect_direct_versions must pick the DIRECT ms@2.1.3, \
             not the transitive ms@1.5.0. Got: {:?}",
            map.get("ms").map(|v| v.to_string()),
        );
        assert_eq!(
            map.get("legacy-pkg").map(|v| v.to_string()),
            Some("1.0.0".to_string())
        );
        assert_eq!(
            map.len(),
            2,
            "transitive ms@1.5.0 must NOT appear in the map"
        );
    }

    /// Reverse the input order: transitive entry comes AFTER the direct
    /// entry. The helper still picks the direct one — order-independent.
    #[test]
    fn collect_direct_versions_picks_direct_regardless_of_input_order() {
        let packages = vec![
            fake_pkg("ms", "2.1.3", true),
            fake_pkg("ms", "1.5.0", false),
        ];
        let map = collect_direct_versions(&packages);
        assert_eq!(
            map.get("ms").map(|v| v.to_string()),
            Some("2.1.3".to_string()),
            "input-order independence: direct entry must be picked even when \
             it appears before the transitive in the input list"
        );
        assert_eq!(map.len(), 1);
    }

    /// Transitive-only packages are EXCLUDED from the map entirely.
    /// (They're not eligible for finalize anyway, but the map should be
    /// minimal so finalize's missing-version error is meaningful.)
    #[test]
    fn collect_direct_versions_excludes_pure_transitives() {
        let packages = vec![
            fake_pkg("ms", "1.5.0", false),
            fake_pkg("legacy-pkg", "1.0.0", true),
        ];
        let map = collect_direct_versions(&packages);
        assert!(
            !map.contains_key("ms"),
            "transitive-only entry must not appear"
        );
        assert!(map.contains_key("legacy-pkg"));
        assert_eq!(map.len(), 1);
    }

    /// Empty input → empty map.
    #[test]
    fn collect_direct_versions_empty_input_returns_empty_map() {
        let map = collect_direct_versions(&[]);
        assert!(map.is_empty());
    }

    /// All transitives → empty map. Used by Phase 33 finalize to detect
    /// "the resolver dropped my staged dep" via the missing-version error.
    #[test]
    fn collect_direct_versions_all_transitive_returns_empty_map() {
        let packages = vec![
            fake_pkg("ms", "1.5.0", false),
            fake_pkg("debug", "4.3.4", false),
        ];
        let map = collect_direct_versions(&packages);
        assert!(map.is_empty());
    }

    /// Versions with prerelease tags must parse correctly.
    #[test]
    fn collect_direct_versions_handles_prerelease_versions() {
        let packages = vec![fake_pkg("react", "19.0.0-rc.1", true)];
        let map = collect_direct_versions(&packages);
        let v = map.get("react").unwrap();
        assert!(v.is_prerelease());
        assert_eq!(v.to_string(), "19.0.0-rc.1");
    }

    /// Unparseable versions are silently dropped (with a tracing warn).
    /// Finalize will then surface a clean missing-version error for the
    /// affected name, instead of panicking on a malformed semver.
    #[test]
    fn collect_direct_versions_drops_unparseable_versions() {
        let packages = vec![
            fake_pkg("react", "18.2.0", true),
            fake_pkg("broken", "not-a-version", true),
        ];
        let map = collect_direct_versions(&packages);
        assert!(map.contains_key("react"));
        assert!(
            !map.contains_key("broken"),
            "unparseable version must be dropped (finalize will surface a clean error)"
        );
    }

    /// Finalize errors loudly if a placeholder entry has no resolved
    /// version in the map. Better to surface this than to silently leave
    /// a `*` in the manifest.
    #[test]
    fn finalize_errors_when_resolved_version_missing_for_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        let staged = stage_packages_to_manifest(
            &pkg_path,
            &["ms".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        // Empty resolved map.
        let result = finalize_packages_in_manifest(
            &staged,
            &HashMap::new(),
            crate::save_spec::SaveFlags::default(),
            crate::save_spec::SaveConfig::default(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ms"));
        assert!(err.contains("placeholder"));
    }

    // ── Phase 2 audit fix #1: D2 migration hint on filtered install no-match ──

    /// Helper: real on-disk workspace fixture so resolve_install_targets can
    /// actually discover it.
    fn write_workspace_for_install_tests(root: &Path, members: &[(&str, &str)]) {
        let workspace_globs: Vec<String> = members.iter().map(|(_, p)| (*p).to_string()).collect();
        let root_pkg = serde_json::json!({
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
            let pkg = serde_json::json!({"name": name, "version": "0.0.0"});
            std::fs::write(
                dir.join("package.json"),
                serde_json::to_string_pretty(&pkg).unwrap(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn run_install_filtered_add_no_match_with_fail_flag_includes_d2_hint_for_bare_names() {
        // Phase 2 audit regression: filtered install must surface the D2
        // substring → glob migration hint when --fail-if-no-match fires AND
        // a filter looks like a bare name.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_for_install_tests(dir.path(), &[("foo", "packages/foo")]);
        let client = lpm_registry::RegistryClient::new();

        let result = run_install_filtered_add(
            &client,
            dir.path(),
            &["react".to_string()],
            false,                // save_dev
            &["app".to_string()], // bare-name filter that matches nothing
            false,                // workspace_root_flag
            true,                 // fail_if_no_match — required for the error path
            false,                // yes — not exercising the prompt here
            true,                 // json_output
            false,                // allow_new
            false,                // force
            crate::save_spec::SaveFlags::default(),
        )
        .await;

        assert!(result.is_err(), "fail_if_no_match must error on no match");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("D2"),
            "error must reference design decision D2, got: {err}"
        );
        assert!(
            err.contains("\"*app*\"") || err.contains("\"*/app\""),
            "error must suggest at least one glob form, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_install_filtered_add_no_match_for_glob_filter_does_not_emit_d2_hint() {
        // Negative case: glob filter is already migrated, no hint needed.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_for_install_tests(dir.path(), &[("foo", "packages/foo")]);
        let client = lpm_registry::RegistryClient::new();

        let result = run_install_filtered_add(
            &client,
            dir.path(),
            &["react".to_string()],
            false,
            &["nonexistent-*".to_string()],
            false,
            true,
            false, // yes
            true,
            false,
            false,
            crate::save_spec::SaveFlags::default(),
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("D2"),
            "glob-only filter must NOT trigger the D2 hint, got: {err}"
        );
    }

    // ── Phase 2 audit fix: install_root must be the member dir, not workspace ──

    #[tokio::test]
    async fn run_install_filtered_add_mutates_targeted_member_manifest_on_fresh_workspace() {
        // GPT audit reproduction: filtered install on a workspace whose root
        // package.json has NO dependencies. Pre-fix this silently dropped
        // the install entirely because run_with_options was called with
        // project_dir=workspace_root, which has empty deps and short-circuits.
        //
        // This test asserts the manifest mutation lands at the targeted
        // member, which is the part of the install pipeline we can verify
        // without network. We can't run the actual install pipeline in
        // unit tests (it needs network), but the manifest mutation is the
        // first step of the workflow and is testable in isolation.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_for_install_tests(
            dir.path(),
            &[
                ("@test/app", "packages/app"),
                ("@test/core", "packages/core"),
            ],
        );

        // Verify the workspace root package.json has NO dependencies
        // (this is the precondition that triggered the bug).
        let root_pkg: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(
            root_pkg.get("dependencies").is_none(),
            "test precondition: workspace root must have no dependencies"
        );

        // Use the install_targets resolver directly — this avoids the
        // network-dependent run_with_options call and verifies the part
        // of the workflow that Phase 2 owns.
        let cwd = dir.path().join("packages").join("core");
        let targets = crate::commands::install_targets::resolve_install_targets(
            &cwd,
            &["@test/app".to_string()],
            false,
            true,
        )
        .unwrap();

        // CRITICAL: install root must be the member dir, not the workspace root
        assert_eq!(targets.member_manifests.len(), 1);
        let install_root =
            crate::commands::install_targets::install_root_for(&targets.member_manifests[0]);
        let expected = dir.path().join("packages").join("app");
        assert_eq!(
            install_root.canonicalize().unwrap(),
            expected.canonicalize().unwrap(),
            "install root for filtered install must be the member dir"
        );
        assert_ne!(
            install_root.canonicalize().unwrap(),
            dir.path().canonicalize().unwrap(),
            "regression: install root must NOT be the workspace root"
        );

        // Now mutate the manifest the way run_install_filtered_add would,
        // and verify the result lands at packages/app. Phase 33: this is
        // the explicit-Exact path, so stage writes the verbatim spec
        // and finalize is a no-op.
        stage_packages_to_manifest(
            &targets.member_manifests[0],
            &["react@18.2.0".to_string()],
            false,
            crate::save_spec::SaveFlags::default(),
            true,
        )
        .unwrap();

        let app_pkg: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/app/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(app_pkg["dependencies"]["react"], "18.2.0");

        // Workspace root must remain unchanged
        let root_after: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(root_after.get("dependencies").is_none());
    }

    // ── Phase 2 audit fix #3 (workspace:^ resolver bug) — diagnostics + repro ──

    /// DIAGNOSTIC: empirically confirm what the resolver sees when a member's
    /// `package.json` declares a cross-member dep via `workspace:^`. This is
    /// the test that distinguished Hypothesis A (rewrite never runs) from
    /// Hypothesis B (rewrite runs and turns `workspace:^` into a concrete
    /// range that the resolver then fails to fetch from the registry).
    ///
    /// The pre-fix behavior was Hypothesis B: `resolve_workspace_protocol`
    /// rewrote `@test/core@workspace:^` to `@test/core@^1.5.0`, the resolver
    /// classified `@test/core` as an npm package (it doesn't start with
    /// `@lpm.dev/`), and the lookup 404'd against the npm upstream proxy.
    ///
    /// The post-fix behavior is "extracted before resolution": the workspace
    /// member is removed from the resolver's input HashMap entirely, and the
    /// install pipeline links it directly from its source dir instead.
    #[test]
    fn workspace_protocol_dep_is_extracted_before_resolver_sees_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Build a workspace where @test/app depends on @test/core via workspace:^
        // and @test/core has a concrete version (1.5.0). Mirrors the user repro.
        let root_pkg = serde_json::json!({
            "name": "monorepo",
            "private": true,
            "workspaces": ["packages/*"],
        });
        std::fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();

        let app_dir = root.join("packages").join("app");
        let core_dir = root.join("packages").join("core");
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::create_dir_all(&core_dir).unwrap();

        let app_pkg = serde_json::json!({
            "name": "@test/app",
            "version": "0.1.0",
            "dependencies": { "@test/core": "workspace:^" },
        });
        let core_pkg = serde_json::json!({
            "name": "@test/core",
            "version": "1.5.0",
        });
        std::fs::write(
            app_dir.join("package.json"),
            serde_json::to_string_pretty(&app_pkg).unwrap(),
        )
        .unwrap();
        std::fs::write(
            core_dir.join("package.json"),
            serde_json::to_string_pretty(&core_pkg).unwrap(),
        )
        .unwrap();

        // Reproduce the prefix of run_with_options exactly:
        let pkg = lpm_workspace::read_package_json(&app_dir.join("package.json")).unwrap();
        let mut deps = pkg.dependencies.clone();
        let workspace = lpm_workspace::discover_workspace(&app_dir)
            .unwrap()
            .unwrap();

        // Pre-fix: deps after `resolve_workspace_protocol` would contain
        // `{"@test/core": "^1.5.0"}` and be passed straight to the resolver,
        // which would call `get_npm_package_metadata("@test/core")` and 404.
        // Post-fix: `extract_workspace_protocol_deps` removes the member from
        // `deps` and returns it as a `WorkspaceMemberLink`.
        let extracted = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap();

        // The resolver-input HashMap must NOT contain @test/core anymore.
        assert!(
            !deps.contains_key("@test/core"),
            "post-fix: @test/core must be stripped from resolver input \
             (pre-fix it was `^1.5.0` and the resolver 404'd against npm)"
        );
        assert!(
            deps.is_empty(),
            "the only declared dep was a workspace member, deps must be empty after extraction"
        );

        // The extracted member metadata must point at the on-disk source dir
        // and the version from the member's own package.json.
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, "@test/core");
        assert_eq!(extracted[0].version, "1.5.0");
        assert_eq!(
            extracted[0].source_dir.canonicalize().unwrap(),
            core_dir.canonicalize().unwrap(),
        );
    }

    /// REGRESSION: Hypothesis-A negative test. Even though the bug turned out
    /// to be Hypothesis B, this case is still load-bearing — if a future
    /// refactor accidentally re-introduces a path where `discover_workspace`
    /// fails to walk up from a member dir, this test catches it. The
    /// member-dir → workspace-root walk MUST keep working for the
    /// `workspace:^` extraction to fire at all.
    #[test]
    fn discover_workspace_from_member_dir_finds_workspace_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[
                ("@test/app", "packages/app"),
                ("@test/core", "packages/core"),
            ],
        );

        // Walking up from any member dir must find the workspace root.
        for member in &["packages/app", "packages/core"] {
            let member_dir = root.join(member);
            let ws = lpm_workspace::discover_workspace(&member_dir)
                .expect("discovery must not error")
                .expect("workspace root must be discoverable from member dir");
            assert_eq!(
                ws.root.canonicalize().unwrap(),
                root.canonicalize().unwrap(),
                "discover_workspace from {member} did not find the workspace root"
            );
        }
    }

    /// REGRESSION: full extraction round-trip on a workspace where two
    /// members reference each other AND the install root has a regular
    /// registry dep too. The extraction must:
    /// 1. Strip the workspace member dep from `deps`
    /// 2. Leave the registry dep in `deps`
    /// 3. Return exactly one `WorkspaceMemberLink` pointing at the right dir
    #[test]
    fn extract_workspace_protocol_deps_only_strips_workspace_protocol_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[
                ("@test/app", "packages/app"),
                ("@test/core", "packages/core"),
            ],
        );

        // Manually rewrite @test/core's manifest with a real version,
        // and @test/app's manifest with both a registry dep AND a workspace dep.
        std::fs::write(
            root.join("packages/core/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/core",
                "version": "2.3.4",
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("packages/app/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/app",
                "version": "0.0.0",
                "dependencies": {
                    "@test/core": "workspace:^",
                    "react": "^18.0.0",
                },
            }))
            .unwrap(),
        )
        .unwrap();

        let app_dir = root.join("packages/app");
        let pkg = lpm_workspace::read_package_json(&app_dir.join("package.json")).unwrap();
        let mut deps = pkg.dependencies.clone();
        let workspace = lpm_workspace::discover_workspace(&app_dir)
            .unwrap()
            .unwrap();

        let extracted = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap();

        // Workspace member stripped, registry dep retained.
        assert!(!deps.contains_key("@test/core"));
        assert_eq!(deps.get("react").map(String::as_str), Some("^18.0.0"));
        assert_eq!(deps.len(), 1);

        // Extraction surfaces the member's source dir + version.
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, "@test/core");
        assert_eq!(extracted[0].version, "2.3.4");
        assert_eq!(
            extracted[0].source_dir.canonicalize().unwrap(),
            root.join("packages/core").canonicalize().unwrap(),
        );
    }

    /// REGRESSION: `workspace:` form variants are all handled. Pre-fix this
    /// would only have caught `workspace:^` because that's what the user repro
    /// used; post-fix the helper handles all forms.
    #[test]
    fn extract_workspace_protocol_deps_handles_all_workspace_protocol_forms() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[
                ("@test/star", "packages/star"),
                ("@test/caret", "packages/caret"),
                ("@test/tilde", "packages/tilde"),
                ("@test/exact", "packages/exact"),
                ("@test/passthrough", "packages/passthrough"),
                ("@test/host", "packages/host"),
            ],
        );
        // Every member needs a concrete version
        for name in ["star", "caret", "tilde", "exact", "passthrough"] {
            std::fs::write(
                root.join(format!("packages/{name}/package.json")),
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": format!("@test/{name}"),
                    "version": "1.0.0",
                }))
                .unwrap(),
            )
            .unwrap();
        }
        std::fs::write(
            root.join("packages/host/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/host",
                "version": "0.0.0",
                "dependencies": {
                    "@test/star": "workspace:*",
                    "@test/caret": "workspace:^",
                    "@test/tilde": "workspace:~",
                    "@test/exact": "workspace:1.0.0",
                    "@test/passthrough": "workspace:>=1.0.0",
                },
            }))
            .unwrap(),
        )
        .unwrap();

        let host_dir = root.join("packages/host");
        let pkg = lpm_workspace::read_package_json(&host_dir.join("package.json")).unwrap();
        let mut deps = pkg.dependencies.clone();
        let workspace = lpm_workspace::discover_workspace(&host_dir)
            .unwrap()
            .unwrap();

        let extracted = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap();

        assert!(
            deps.is_empty(),
            "all five workspace: deps must be stripped, deps={deps:?}"
        );
        assert_eq!(extracted.len(), 5, "all five forms must be extracted");
        let names: std::collections::HashSet<&str> =
            extracted.iter().map(|m| m.name.as_str()).collect();
        for n in [
            "@test/star",
            "@test/caret",
            "@test/tilde",
            "@test/exact",
            "@test/passthrough",
        ] {
            assert!(names.contains(n), "missing extracted member {n}");
        }
    }

    /// REGRESSION: a `workspace:` reference to an unknown member must hard
    /// error so users don't silently install nothing. Mirrors the validation
    /// `resolve_workspace_protocol` already enforces.
    #[test]
    fn extract_workspace_protocol_deps_errors_on_unknown_member() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(root, &[("@test/app", "packages/app")]);
        std::fs::write(
            root.join("packages/app/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/app",
                "version": "0.0.0",
                "dependencies": { "@test/missing": "workspace:^" },
            }))
            .unwrap(),
        )
        .unwrap();

        let app_dir = root.join("packages/app");
        let pkg = lpm_workspace::read_package_json(&app_dir.join("package.json")).unwrap();
        let mut deps = pkg.dependencies.clone();
        let workspace = lpm_workspace::discover_workspace(&app_dir)
            .unwrap()
            .unwrap();

        let err = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("@test/missing"),
            "error must name the missing member, got: {msg}"
        );
        assert!(
            msg.contains("not a workspace member") || msg.contains("Available"),
            "error must explain what's wrong, got: {msg}"
        );
    }

    /// REGRESSION: when ALL declared deps are workspace members, the install
    /// pipeline must still link them. Pre-fix the empty-deps short-circuit at
    /// install.rs line ~172 would return early after extraction; post-fix the
    /// short-circuit is gated on "deps empty AND workspace member list empty".
    #[test]
    fn link_workspace_members_creates_node_modules_symlink_to_member_source_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[
                ("@test/app", "packages/app"),
                ("@test/core", "packages/core"),
            ],
        );
        // Give @test/core a real version
        std::fs::write(
            root.join("packages/core/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/core",
                "version": "2.0.0",
            }))
            .unwrap(),
        )
        .unwrap();

        let app_dir = root.join("packages/app");
        let core_dir = root.join("packages/core");

        let members = vec![WorkspaceMemberLink {
            name: "@test/core".to_string(),
            version: "2.0.0".to_string(),
            source_dir: core_dir.clone(),
        }];

        let linked = link_workspace_members(&app_dir, &members).unwrap();
        assert_eq!(linked, 1);

        // node_modules/@test/core must exist and resolve back to packages/core
        let link_path = app_dir.join("node_modules").join("@test").join("core");
        assert!(
            link_path.symlink_metadata().is_ok(),
            "expected node_modules/@test/core to exist"
        );
        let resolved = std::fs::canonicalize(&link_path).unwrap();
        assert_eq!(
            resolved,
            core_dir.canonicalize().unwrap(),
            "symlink must resolve to the workspace member's source directory"
        );
    }

    /// REGRESSION: re-running `link_workspace_members` is idempotent and
    /// re-links over a stale symlink. The linker's stale-symlink cleanup
    /// pass would otherwise remove our workspace symlinks on every install
    /// (they're not in `direct_names`), so the post-link helper has to
    /// tolerate "the path already exists from a previous run" gracefully.
    #[test]
    fn link_workspace_members_is_idempotent_across_repeated_calls() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[
                ("@test/app", "packages/app"),
                ("@test/core", "packages/core"),
            ],
        );

        let app_dir = root.join("packages/app");
        let core_dir = root.join("packages/core");

        let members = vec![WorkspaceMemberLink {
            name: "@test/core".to_string(),
            version: "0.0.0".to_string(),
            source_dir: core_dir.clone(),
        }];

        link_workspace_members(&app_dir, &members).unwrap();
        link_workspace_members(&app_dir, &members).unwrap();
        link_workspace_members(&app_dir, &members).unwrap();

        let link_path = app_dir.join("node_modules").join("@test").join("core");
        let resolved = std::fs::canonicalize(&link_path).unwrap();
        assert_eq!(resolved, core_dir.canonicalize().unwrap());
    }

    // ────────────────────────────────────────────────────────────────────
    // 2026-04-16: `lpm install` resolves devDependencies (bug fix audit).
    // Pre-fix, `run_with_options` only cloned `pkg.dependencies` — so
    // `lpm install -D vitest` landed vitest in the manifest but never
    // resolved or linked it. These tests pin the merge contract used
    // right after `let mut deps = pkg.dependencies.clone();`.
    // ────────────────────────────────────────────────────────────────────

    /// Reproduces the exact merge step that `run_with_options` performs
    /// immediately after cloning `pkg.dependencies`. Kept in sync with the
    /// inline loop in `run_with_options` — if the production code moves to
    /// a helper, point this test at it.
    fn merge_dev_dependencies_into_deps(
        deps: &mut HashMap<String, String>,
        dev_deps: &HashMap<String, String>,
    ) {
        for (name, range) in dev_deps {
            deps.entry(name.clone()).or_insert_with(|| range.clone());
        }
    }

    #[test]
    fn install_merges_dev_dependencies_into_resolver_input() {
        let mut deps: HashMap<String, String> =
            [("react".to_string(), "^18.0.0".to_string())].into();
        let dev_deps: HashMap<String, String> =
            [("vitest".to_string(), "^1.0.0".to_string())].into();

        merge_dev_dependencies_into_deps(&mut deps, &dev_deps);

        assert_eq!(deps.len(), 2);
        assert_eq!(deps.get("react").map(String::as_str), Some("^18.0.0"));
        assert_eq!(deps.get("vitest").map(String::as_str), Some("^1.0.0"));
    }

    #[test]
    fn install_merge_lets_dependencies_win_on_conflict() {
        // If the same name appears in both sections, `dependencies` wins.
        // This mirrors the production-contract intuition: devDeps must not
        // shadow the explicit `dependencies` declaration even if someone
        // accidentally adds a second entry.
        let mut deps: HashMap<String, String> =
            [("lodash".to_string(), "^4.17.0".to_string())].into();
        let dev_deps: HashMap<String, String> =
            [("lodash".to_string(), "^3.0.0".to_string())].into();

        merge_dev_dependencies_into_deps(&mut deps, &dev_deps);

        assert_eq!(deps.len(), 1);
        assert_eq!(
            deps.get("lodash").map(String::as_str),
            Some("^4.17.0"),
            "dependencies must win over devDependencies on conflict"
        );
    }

    #[test]
    fn install_merge_is_noop_when_dev_dependencies_empty() {
        let mut deps: HashMap<String, String> =
            [("react".to_string(), "^18.0.0".to_string())].into();
        let original = deps.clone();
        let dev_deps: HashMap<String, String> = HashMap::new();

        merge_dev_dependencies_into_deps(&mut deps, &dev_deps);

        assert_eq!(deps, original);
    }

    #[test]
    fn install_merge_populates_deps_when_only_dev_dependencies_declared() {
        // `lpm install -D vitest` on a project with no regular deps must
        // still produce a non-empty resolver input — this is the exact
        // case the pre-2026-04-16 bug silently no-op'd.
        let mut deps: HashMap<String, String> = HashMap::new();
        let dev_deps: HashMap<String, String> =
            [("vitest".to_string(), "^1.0.0".to_string())].into();

        merge_dev_dependencies_into_deps(&mut deps, &dev_deps);

        assert_eq!(deps.len(), 1);
        assert_eq!(deps.get("vitest").map(String::as_str), Some("^1.0.0"));
    }

    #[test]
    fn install_merge_mirrors_production_call_site_against_live_manifest() {
        // Parse a representative package.json through the same typed reader
        // the install path uses, then run the merge and assert the result.
        // This catches regressions where `pkg.dev_dependencies` stops being
        // parsed (e.g., serde rename drift) — a higher-layer guard than
        // the three HashMap-level tests above.
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        std::fs::write(
            &pkg_path,
            r#"{
                "name": "proj",
                "dependencies": { "react": "^18.0.0" },
                "devDependencies": { "vitest": "^1.0.0", "tsup": "^8.0.0" }
            }"#,
        )
        .unwrap();

        let pkg = lpm_workspace::read_package_json(&pkg_path).unwrap();
        let mut deps = pkg.dependencies.clone();
        merge_dev_dependencies_into_deps(&mut deps, &pkg.dev_dependencies);

        assert_eq!(
            deps.len(),
            3,
            "react + vitest + tsup must all flow into the resolver input"
        );
        assert!(deps.contains_key("react"));
        assert!(deps.contains_key("vitest"));
        assert!(deps.contains_key("tsup"));
    }

    // ────────────────────────────────────────────────────────────────────
    // 2026-04-16 (D-impl-5): multi-member confirmation prompt.
    //
    // The bypass tests pin the CI/script-safe paths, and the PTY-backed
    // test below exercises the real interactive "decline → abort" branch
    // through `stdin.is_terminal()` + `read_line`.
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn confirm_multi_member_mutation_with_yes_flag_bypasses_prompt() {
        let _lock = confirm_prompt_test_lock();
        let manifests = vec![
            PathBuf::from("/tmp/workspace/packages/a/package.json"),
            PathBuf::from("/tmp/workspace/packages/b/package.json"),
        ];
        let result =
            confirm_multi_member_mutation("Adding", 1, &manifests, /* yes */ true, false);
        assert!(
            result.is_ok(),
            "--yes must bypass the prompt and return Ok regardless of stdin state"
        );
    }

    #[test]
    fn confirm_multi_member_mutation_in_json_mode_bypasses_prompt() {
        let _lock = confirm_prompt_test_lock();
        let manifests = vec![
            PathBuf::from("/tmp/workspace/packages/a/package.json"),
            PathBuf::from("/tmp/workspace/packages/b/package.json"),
        ];
        let result = confirm_multi_member_mutation(
            "Removing", 2, &manifests, /* yes */ false, /* json_output */ true,
        );
        assert!(
            result.is_ok(),
            "JSON mode must bypass the prompt — agents get a single parseable result"
        );
    }

    #[test]
    fn confirm_multi_member_mutation_with_non_tty_stdin_bypasses_prompt() {
        let _lock = confirm_prompt_test_lock();
        // When tests run under `cargo nextest run`, the process's stdin is
        // piped (NOT a TTY). That alone must bypass the prompt. If this
        // test ever hangs, the non-TTY bypass is broken and would also
        // hang real CI invocations of `lpm install --filter "ui-*"`.
        let manifests = vec![
            PathBuf::from("/tmp/workspace/packages/a/package.json"),
            PathBuf::from("/tmp/workspace/packages/b/package.json"),
        ];
        let result = confirm_multi_member_mutation(
            "Adding", 1, &manifests, /* yes */ false, /* json_output */ false,
        );
        assert!(
            result.is_ok(),
            "non-TTY stdin must bypass the prompt so scripted / CI invocations don't hang. \
             If this test hangs or fails, `is_terminal()` on stdin returned true under test \
             harness and the CI bypass is broken."
        );
    }

    #[test]
    fn confirm_multi_member_mutation_accepts_empty_manifest_list() {
        let _lock = confirm_prompt_test_lock();
        // Defensive: callers only invoke this when `multi_member == true`
        // (length ≥ 2), but the helper must still behave sanely on 0-1
        // entries rather than panicking or over-indexing.
        let empty: Vec<PathBuf> = Vec::new();
        let result = confirm_multi_member_mutation("Adding", 0, &empty, true, false);
        assert!(
            result.is_ok(),
            "empty manifest list with --yes must not error"
        );
    }

    #[cfg(unix)]
    #[test]
    fn confirm_multi_member_mutation_decline_on_tty_returns_abort_error() {
        let manifests = vec![
            PathBuf::from("/tmp/workspace/packages/a/package.json"),
            PathBuf::from("/tmp/workspace/packages/b/package.json"),
        ];

        let err = with_tty_stdin_input("n\n", || {
            confirm_multi_member_mutation(
                "Removing", 2, &manifests, /* yes */ false, /* json_output */ false,
            )
            .unwrap_err()
        });

        match err {
            LpmError::Script(message) => {
                assert!(message.contains("aborted by user"));
                assert!(message.contains("no package.json was modified"));
                assert!(message.contains("\"n\""));
            }
            other => panic!("expected Script error, got {other:?}"),
        }
    }

    // ─── Phase 41: P4 split-context dedup ────────────────────────────
    //
    // Bug: `resolved_to_install_packages` maps `ResolverPackage` → canonical
    // name via `canonical_name()`, which strips the Phase 40 P4 split
    // `context` suffix. When the resolver emits multiple ResolvedPackage
    // rows for the same `(canonical_name, version)` — one per split scope
    // — the pre-fix implementation produced N identical `InstallPackage`
    // rows. Downstream, `link_finalize` spawned N parallel Phase 3
    // symlink-creation tasks for the same root path, which raced on
    // `std::os::unix::fs::symlink` and returned `EEXIST` to whichever
    // thread lost, aborting the install with
    // "IO error: File exists (os error 17)".
    //
    // Reproduced on the decision-gate fixture (`eslint@^9` + `ajv@^8`
    // restored) in ~4 of 5 `--json` cold installs before this fix.
    //
    // Contract: `resolved_to_install_packages` must collapse duplicates
    // by `(canonical_name, version)` so every downstream stage sees one
    // row per physical package.

    use lpm_resolver::NpmVersion;
    use lpm_resolver::ResolverPackage;

    fn fake_resolved(name: &str, version: &str, context: Option<&str>) -> ResolvedPackage {
        let pkg = match context {
            Some(ctx) => ResolverPackage::npm(name).with_context(ctx),
            None => ResolverPackage::npm(name),
        };
        ResolvedPackage {
            package: pkg,
            version: NpmVersion::parse(version).expect("valid version"),
            dependencies: Vec::new(),
            aliases: HashMap::new(),
            tarball_url: None,
            integrity: None,
        }
    }

    #[test]
    fn resolved_to_install_packages_dedups_p4_split_duplicates() {
        // Four resolver outputs for `cross-spawn@7.0.6`: one un-scoped
        // + three scoped under different parents. `canonical_name()`
        // collapses all four to `"cross-spawn"`.
        let resolved = vec![
            fake_resolved("cross-spawn", "7.0.6", None),
            fake_resolved("cross-spawn", "7.0.6", Some("parent1")),
            fake_resolved("cross-spawn", "7.0.6", Some("parent2")),
            fake_resolved("cross-spawn", "7.0.6", Some("parent3")),
        ];
        let deps: HashMap<String, String> =
            [("cross-spawn".to_string(), "^7.0.0".to_string())].into();

        let installed = resolved_to_install_packages(&resolved, &deps, &HashMap::new());

        assert_eq!(
            installed.len(),
            1,
            "P4 split contexts for the same (canonical_name, version) \
             MUST dedup to exactly one InstallPackage row — got {} rows. \
             Duplicates cascade into link_pairs and race link_finalize's \
             Phase 3 root symlink creation.",
            installed.len(),
        );
        assert_eq!(installed[0].name, "cross-spawn");
        assert_eq!(installed[0].version, "7.0.6");
        assert!(
            installed[0].is_direct,
            "direct_target_names contains 'cross-spawn', merged row must be direct"
        );
        assert_eq!(
            installed[0].root_link_names.as_deref(),
            Some(&["cross-spawn".to_string()][..]),
            "root_link_names comes from root_link_map keyed on \
             (canonical_name, version) — must survive dedup"
        );
    }

    #[test]
    fn resolved_to_install_packages_keeps_distinct_versions() {
        // Different versions of the same name must NOT be deduped — only
        // the (canonical_name, version) tuple is the dedup key. Both
        // 5.6.2 and 4.1.2 need their own `.lpm/` store entries.
        let resolved = vec![
            fake_resolved("chalk", "5.6.2", None),
            fake_resolved("chalk", "4.1.2", Some("parent1")),
        ];
        let deps: HashMap<String, String> = [("chalk".to_string(), "^5.0.0".to_string())].into();

        let installed = resolved_to_install_packages(&resolved, &deps, &HashMap::new());

        assert_eq!(installed.len(), 2, "distinct versions must be preserved");
        let mut versions: Vec<String> = installed.iter().map(|p| p.version.clone()).collect();
        versions.sort();
        assert_eq!(versions, vec!["4.1.2".to_string(), "5.6.2".to_string()]);
    }

    #[test]
    fn resolved_to_install_packages_dedups_preserves_first_order() {
        // When the resolver emits the un-scoped entry first, that's the
        // one whose fields we keep. Later scoped copies are discarded.
        // Stability matters — downstream consumers (lockfile writer,
        // snapshot tests) assume a deterministic order.
        let resolved = vec![
            fake_resolved("nanoid", "3.3.11", None),
            fake_resolved("nanoid", "3.3.11", Some("parent1")),
            fake_resolved("nanoid", "3.3.11", Some("parent2")),
        ];
        let deps: HashMap<String, String> = [("nanoid".to_string(), "^3.3.0".to_string())].into();

        let installed = resolved_to_install_packages(&resolved, &deps, &HashMap::new());

        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].version, "3.3.11");
    }

    // ── Phase 43 P43-2 regression tests ─────────────────────────────────────

    /// Phase 43 P43-2 regression test #8 — `handle_tarball_not_found`
    /// must delete the project's own `lpm.lock` / `lpm.lockb`, not
    /// CWD-relative files. Before the P43-2 fix, a programmatic
    /// install from a nested directory would leak stale state.
    #[test]
    fn phase43_handle_tarball_not_found_honors_project_dir() {
        let proj = tempfile::tempdir().unwrap();
        let project_dir = proj.path();

        let lock_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
        let lockb_path = project_dir.join(lpm_lockfile::BINARY_LOCKFILE_NAME);
        std::fs::write(&lock_path, "# stale lockfile").unwrap();
        std::fs::write(&lockb_path, b"LPMBfake").unwrap();
        assert!(lock_path.exists());
        assert!(lockb_path.exists());

        // Construct a real client — we only care that
        // `invalidate_metadata_cache` + file-delete run. No network.
        let client = Arc::new(RegistryClient::new());
        let err = handle_tarball_not_found(&client, "some-pkg", "1.0.0", project_dir);

        // Lockfiles in the PROJECT directory are gone.
        assert!(!lock_path.exists(), "project_dir/lpm.lock must be deleted");
        assert!(
            !lockb_path.exists(),
            "project_dir/lpm.lockb must be deleted"
        );
        // Error message references the package for user diagnostics.
        assert!(matches!(err, LpmError::NotFound(ref msg) if msg.contains("some-pkg@1.0.0")));
    }

    /// Phase 43 P43-2 regression test #9 — the fast-path writeback
    /// trigger fires on v1 → v2 binary migration even when no URL
    /// diverged. We can't easily test the full install here without
    /// a mock server, but we CAN test the trigger condition:
    /// `try_lockfile_fast_path` returns `needs_binary_upgrade = true`
    /// when the on-disk `lpm.lockb` is version 1.
    #[test]
    fn phase43_try_lockfile_fast_path_flags_v1_binary_for_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
        let binary_path = dir.path().join(lpm_lockfile::BINARY_LOCKFILE_NAME);

        // Write a valid TOML lockfile with one package matching the
        // single declared root dep.
        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.write_to_file(&lockfile_path).unwrap();

        // Hand-roll a v1 `lpm.lockb` header — just the magic + v1 +
        // zero packages + header-sized string table. `open` rejects
        // with `UnsupportedVersion`, triggering the `needs_binary_upgrade`
        // branch.
        let mut v1_bytes = Vec::with_capacity(16);
        v1_bytes.extend_from_slice(b"LPMB");
        v1_bytes.extend_from_slice(&1u32.to_le_bytes());
        v1_bytes.extend_from_slice(&0u32.to_le_bytes());
        v1_bytes.extend_from_slice(&16u32.to_le_bytes());
        // Write bytes AFTER the TOML so `read_fast` prefers binary
        // (mtime-wise).
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&binary_path, &v1_bytes).unwrap();

        // `read_fast` in the 2nd-round follow-up deletes v1 binaries
        // (`found < BINARY_VERSION`), so by the time `try_lockfile_fast_path`
        // gets to the `BinaryLockfileReader::open` probe, the binary
        // might have been deleted already. Either way,
        // `needs_binary_upgrade` should be true (missing or stale).
        //
        // Actually the order is: `try_lockfile_fast_path` probes the
        // binary FIRST (to check `needs_binary_upgrade`), THEN calls
        // `read_fast`. So at probe time, the v1 binary is still on
        // disk and `open` returns `UnsupportedVersion`.

        let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
        let client = RegistryClient::new();
        let gate_stats = GateStats::default();
        let result = try_lockfile_fast_path(&lockfile_path, &deps, &client, &gate_stats)
            .expect("fast path should succeed via TOML fallback");

        assert!(
            result.needs_binary_upgrade,
            "v1 binary on disk must set needs_binary_upgrade=true so the \
             writeback trigger fires"
        );
        assert_eq!(result.packages.len(), 1);
        assert_eq!(result.packages[0].name, "lodash");
    }

    /// Phase 43 P43-2 regression test #9b — `try_lockfile_fast_path`
    /// returns `needs_binary_upgrade = true` when `lpm.lockb` is
    /// missing entirely (no binary ever written). Same code path as
    /// the v1→v2 migration case but covers fresh projects that
    /// ship only the TOML lockfile.
    #[test]
    fn phase43_try_lockfile_fast_path_flags_missing_binary_for_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.write_to_file(&lockfile_path).unwrap();
        // NO binary file written.

        let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
        let client = RegistryClient::new();
        let gate_stats = GateStats::default();
        let result = try_lockfile_fast_path(&lockfile_path, &deps, &client, &gate_stats)
            .expect("fast path should succeed with only TOML");

        assert!(
            result.needs_binary_upgrade,
            "missing lpm.lockb must set needs_binary_upgrade=true"
        );
    }

    /// Phase 43 P43-2 regression test — the writeback trigger skips
    /// when the binary is current AND no URL diverged (true happy
    /// path). `needs_binary_upgrade` is false when a v2 binary
    /// exists and opens cleanly.
    #[test]
    fn phase43_try_lockfile_fast_path_skips_upgrade_when_binary_current() {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        // `write_all` writes BOTH the TOML and the v2 binary, so the
        // binary is current by construction.
        lf.write_all(&lockfile_path).unwrap();

        let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
        let client = RegistryClient::new();
        let gate_stats = GateStats::default();
        let result = try_lockfile_fast_path(&lockfile_path, &deps, &client, &gate_stats)
            .expect("fast path should succeed with both TOML + v2 binary");

        assert!(
            !result.needs_binary_upgrade,
            "current v2 binary must NOT trigger needs_binary_upgrade"
        );
    }

    /// Phase 43 P43-2 **failing-test-first retrofit** (2026-04-18).
    ///
    /// Core Phase 43 contract: when the lockfile stores a tarball
    /// URL and the gate accepts it, `try_lockfile_fast_path` MUST
    /// populate `InstallPackage.tarball_url = Some(url)`. Without
    /// this, every warm install still pays the per-package metadata
    /// round-trip — i.e., Phase 43 is a no-op.
    ///
    /// Pre-fix (the `tarball_url: None` stub at install.rs:~2908),
    /// this test fails — the field stays `None` regardless of
    /// lockfile content. Empirically verified 2026-04-18 by
    /// surgically reverting the gate logic to the pre-fix stub:
    /// this test FAILED in that world (expected `Some(url)`, got
    /// `None`), passes with the gate in place. Retrofits the
    /// methodology reminder #2 contract.
    #[test]
    fn phase43_gate_accepted_url_populates_tarball_url() {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

        let canonical_url = "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz";
        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-test".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: Some(canonical_url.to_string()),
        });
        lf.write_all(&lockfile_path).unwrap();

        let deps: HashMap<String, String> = [("lodash".to_string(), "^4.17.0".to_string())].into();
        let client = RegistryClient::new();
        let gate_stats = GateStats::default();
        let result = try_lockfile_fast_path(&lockfile_path, &deps, &client, &gate_stats)
            .expect("fast path should succeed on valid lockfile");

        assert_eq!(result.packages.len(), 1);
        assert_eq!(
            result.packages[0].tarball_url.as_deref(),
            Some(canonical_url),
            "gate-accepted cached URL must flow into InstallPackage.tarball_url \
             so the fetch pipeline can skip the metadata round-trip"
        );

        use std::sync::atomic::Ordering;
        assert_eq!(gate_stats.origin_mismatch.load(Ordering::Relaxed), 0);
        assert_eq!(gate_stats.shape_mismatch.load(Ordering::Relaxed), 0);
        assert_eq!(gate_stats.scheme_mismatch.load(Ordering::Relaxed), 0);
    }

    /// Phase 43 P43-2 **failing-test-first retrofit** (2026-04-18).
    ///
    /// Complement to the acceptance test: gate-REJECTED URLs must
    /// downgrade to `None` AND bump the matching mismatch counter.
    /// Three sub-cases: RejectedShape, RejectedOrigin, RejectedScheme.
    /// Under the pre-fix stub, counters stay at 0 — test fails on
    /// the counter assertions. Empirically verified FAILED under
    /// the pre-fix stub (2026-04-18).
    #[test]
    fn phase43_gate_rejected_urls_downgrade_to_none_with_telemetry() {
        use std::sync::atomic::Ordering;

        let run_gate = |tarball: &str, client: &RegistryClient| {
            let dir = tempfile::tempdir().unwrap();
            let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);
            let mut lf = lpm_lockfile::Lockfile::new();
            lf.add_package(lpm_lockfile::LockedPackage {
                name: "victim".to_string(),
                version: "1.0.0".to_string(),
                source: Some("registry+https://registry.npmjs.org".to_string()),
                integrity: Some("sha512-test".to_string()),
                dependencies: vec![],
                alias_dependencies: vec![],
                tarball: Some(tarball.to_string()),
            });
            lf.write_all(&lockfile_path).unwrap();

            let deps: HashMap<String, String> =
                [("victim".to_string(), "^1.0.0".to_string())].into();
            let gate_stats = GateStats::default();
            let result = try_lockfile_fast_path(&lockfile_path, &deps, client, &gate_stats)
                .expect("fast path should succeed even with a gate-rejected URL");
            (result, gate_stats, dir)
        };

        // (1) RejectedShape — `.tgz` suffix + matching origin +
        // HTTPS, but no `/-/` segment. H1 SSRF defense.
        let client = RegistryClient::new();
        let (result, stats, _dir) =
            run_gate("https://registry.npmjs.org/api/admin/foo.tgz", &client);
        assert_eq!(result.packages[0].tarball_url, None);
        assert_eq!(stats.shape_mismatch.load(Ordering::Relaxed), 1);
        assert_eq!(stats.origin_mismatch.load(Ordering::Relaxed), 0);
        assert_eq!(stats.scheme_mismatch.load(Ordering::Relaxed), 0);

        // (2) RejectedOrigin — canonical shape but origin doesn't
        // match the client's `base_url` / `npm_registry_url`.
        let mirror_client = RegistryClient::new().with_base_url("http://localhost:9999");
        let (result, stats, _dir) = run_gate(
            "https://some-other-mirror.com/foo/-/foo-1.0.0.tgz",
            &mirror_client,
        );
        assert_eq!(result.packages[0].tarball_url, None);
        assert_eq!(stats.origin_mismatch.load(Ordering::Relaxed), 1);
        assert_eq!(stats.shape_mismatch.load(Ordering::Relaxed), 0);

        // (3) RejectedScheme — HTTP (non-localhost) at a matching
        // host is scheme-rejected.
        let (result, stats, _dir) = run_gate(
            "http://registry.npmjs.org/foo/-/foo-1.0.0.tgz",
            &RegistryClient::new(),
        );
        assert_eq!(result.packages[0].tarball_url, None);
        assert_eq!(stats.scheme_mismatch.load(Ordering::Relaxed), 1);
    }

    /// Phase 43 P43-2 **failing-test-first retrofit** (2026-04-18).
    ///
    /// Pre-Phase-43 lockfile shape: `tarball = None`. Fast path
    /// must produce `InstallPackage.tarball_url = None` with no
    /// counters bumped. Boundary-case guard — passes in both pre-
    /// and post-fix states, but documents the contract explicitly.
    #[test]
    fn phase43_no_stored_tarball_produces_none_install_package_url() {
        let dir = tempfile::tempdir().unwrap();
        let lockfile_path = dir.path().join(lpm_lockfile::LOCKFILE_NAME);

        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "old-entry".to_string(),
            version: "1.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: Some("sha512-test".to_string()),
            dependencies: vec![],
            alias_dependencies: vec![],
            tarball: None,
        });
        lf.write_all(&lockfile_path).unwrap();

        let deps: HashMap<String, String> =
            [("old-entry".to_string(), "^1.0.0".to_string())].into();
        let client = RegistryClient::new();
        let gate_stats = GateStats::default();
        let result = try_lockfile_fast_path(&lockfile_path, &deps, &client, &gate_stats)
            .expect("fast path should succeed on pre-Phase-43 lockfile");

        assert_eq!(result.packages[0].tarball_url, None);

        use std::sync::atomic::Ordering;
        assert_eq!(gate_stats.origin_mismatch.load(Ordering::Relaxed), 0);
        assert_eq!(gate_stats.shape_mismatch.load(Ordering::Relaxed), 0);
        assert_eq!(gate_stats.scheme_mismatch.load(Ordering::Relaxed), 0);
    }
}
