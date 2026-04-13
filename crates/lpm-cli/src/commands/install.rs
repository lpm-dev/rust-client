use crate::output;
use crate::overrides_state;
use crate::patch_engine;
use crate::patch_state;
use indicatif::{ProgressBar, ProgressStyle}; // kept for concurrent download progress bar
use lpm_common::LpmError;
use lpm_linker::{LinkResult, LinkTarget, MaterializedPackage};
use lpm_registry::RegistryClient;
use lpm_resolver::{
    OverrideHit, OverrideSet, ResolvedPackage, StreamingPrefetch, check_unmet_peers,
    parse_metadata_to_cache_info, resolve_with_prefetch,
};
use lpm_store::PackageStore;
use lpm_workspace::PatchedDependencyEntry;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Maximum number of concurrent tarball downloads.
const MAX_CONCURRENT_DOWNLOADS: usize = 16;

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
    /// Dependencies: (dep_name, dep_version)
    dependencies: Vec<(String, String)>,
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

    let mut deps = pkg.dependencies.clone();

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

        let locked = try_lockfile_fast_path(&lockfile_path, &deps).ok_or_else(|| {
            LpmError::Registry(
                "--offline requires a lockfile. Run `lpm install` online first.".into(),
            )
        })?;
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
        try_lockfile_fast_path(&lockfile_path, &deps)
    };
    // **Phase 32 Phase 5** — applied-override trace for the rest of the
    // install pipeline. Empty for the lockfile-fast-path branch (we
    // preserve the previously-recorded trace from disk in that case);
    // populated for fresh resolution from the resolver's apply log.
    let mut applied_overrides: Vec<OverrideHit> = Vec::new();

    let (mut packages, resolve_ms, used_lockfile) = match lockfile_result {
        Some(locked_packages) => {
            if !json_output {
                output::info(&format!(
                    "Using lockfile ({} packages)",
                    locked_packages.len().to_string().bold()
                ));
            }
            (locked_packages, 0u128, true)
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

            // Phase 36: streaming batch/resolve overlap.
            //
            // Instead of waiting for the full deep batch to complete (~2s),
            // we spawn the batch as a background producer and start the
            // resolver as soon as root-level packages arrive (~400ms).
            // The resolver reads from the streaming cache concurrently
            // while deeper transitive levels continue streaming in.
            //
            // Fallback: if the batch fails or times out, the resolver's
            // provider-internal batching handles all fetches — equivalent
            // to pre-Phase-36 behavior minus the initial wait.
            let streaming = Arc::new(StreamingPrefetch::new());
            // JoinHandle for the converter task — aborted after resolution to
            // drop the receiver, which cancels the producer via channel close.
            let mut converter_handle: Option<tokio::task::JoinHandle<()>> = None;

            if !dep_names.is_empty() && !cache_has_all {
                let batch_start = Instant::now();

                // Channel for raw (name, PackageMetadata) entries from lpm-registry
                let (entry_tx, mut entry_rx) =
                    tokio::sync::mpsc::channel::<(String, lpm_registry::PackageMetadata)>(64);

                // Root-set-ready barrier: fires when all requested root packages
                // have been parsed and inserted into the streaming cache.
                let (root_ready_tx, root_ready_rx) = tokio::sync::oneshot::channel::<()>();

                // Task 1: HTTP producer — calls the streaming batch API in lpm-registry,
                // sends raw entries over the channel. Respects crate boundary: lpm-registry
                // has no knowledge of resolver types. On error, marks the streaming cache
                // as errored so consumers know this was a failure, not a clean EOF.
                let client_for_producer = arc_client.clone();
                let names_for_producer = dep_names.clone();
                let streaming_for_producer = streaming.clone();
                tokio::spawn(async move {
                    match client_for_producer
                        .batch_metadata_deep_streaming(&names_for_producer, entry_tx)
                        .await
                    {
                        Ok(count) => {
                            tracing::debug!(
                                "streaming batch producer complete: {count} entries in {}ms",
                                batch_start.elapsed().as_millis()
                            );
                        }
                        Err(e) => {
                            tracing::warn!("streaming batch producer failed: {e}");
                            streaming_for_producer.mark_errored();
                        }
                    }
                });

                // Task 2: Converter — receives raw entries, transforms to CachedPackageInfo
                // (crossing the lpm-registry → lpm-resolver type boundary), inserts into
                // the shared streaming cache, and signals the root-set-ready barrier.
                //
                // This task's JoinHandle is kept so we can abort it after resolution.
                // Aborting drops entry_rx, which causes the producer's tx.send() to
                // return Err → producer stops reading the HTTP stream. This is the
                // cancellation path: once the resolver is done, no more work is wasted.
                let streaming_for_converter = streaming.clone();
                let root_names = dep_names.clone();
                converter_handle = Some(tokio::spawn(async move {
                    let mut root_ready_tx = Some(root_ready_tx);

                    while let Some((name, metadata)) = entry_rx.recv().await {
                        let is_npm = !name.starts_with("@lpm.dev/");
                        let info = parse_metadata_to_cache_info(&metadata, is_npm);
                        streaming_for_converter.insert(name, info);

                        // Check if all root packages have arrived
                        if root_ready_tx.is_some()
                            && streaming_for_converter.contains_all(&root_names)
                            && let Some(tx) = root_ready_tx.take()
                        {
                            let _ = tx.send(());
                        }
                    }

                    // Stream ended (producer finished or channel closed).
                    // Only mark done if the producer didn't already mark_errored.
                    if !streaming_for_converter.has_errored() {
                        streaming_for_converter.mark_done();
                    }
                }));

                // Wait for root set OR timeout OR producer failure.
                // 5s is generous for slow connections, short enough to not hang.
                let root_ready =
                    tokio::time::timeout(std::time::Duration::from_secs(5), root_ready_rx).await;

                match root_ready {
                    Ok(Ok(())) => {
                        tracing::debug!(
                            "root set ready: {} entries in streaming cache ({}ms)",
                            streaming.len(),
                            batch_start.elapsed().as_millis()
                        );
                    }
                    Ok(Err(_)) => {
                        // Channel dropped before root set complete — partial delivery
                        // or producer error. Proceed with whatever we have.
                        tracing::warn!(
                            "streaming batch ended before root set complete ({} entries cached)",
                            streaming.len()
                        );
                        if streaming.is_empty() && !json_output {
                            output::warn(
                                "Batch prefetch failed — falling back to sequential resolution (this will be slower).",
                            );
                        }
                    }
                    Err(_) => {
                        // Timeout — server is very slow. Proceed with partial cache.
                        tracing::warn!(
                            "root set barrier timed out after 5s ({} entries cached)",
                            streaming.len()
                        );
                    }
                }
            }

            // Start resolver. The provider checks the streaming cache at
            // batch-decision points and in ensure_cached(). When streaming
            // was not started (warm install or empty deps), the streaming
            // cache is empty and the provider uses existing batch logic.
            let streaming_opt = if converter_handle.is_some() {
                Some(streaming.clone())
            } else {
                None
            };

            let resolve_result = resolve_with_prefetch(
                arc_client.clone(),
                deps.clone(),
                override_set.clone(),
                None, // Phase 36: streaming cache replaces the old pre-seeded batch map
                streaming_opt,
            )
            .await;

            // Phase 36: abort the converter task on BOTH success and failure.
            // This drops entry_rx, which causes the producer's tx.send()
            // to fail, stopping the HTTP stream read. Without this, a
            // resolution failure would leave the background tasks alive
            // doing wasted metadata work until the channel naturally closes.
            if let Some(handle) = converter_handle.take() {
                handle.abort();
                streaming.mark_done();
            }

            let resolve_result = resolve_result
                .map_err(|e| LpmError::Registry(format!("resolution failed: {e}")))?;

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

            let packages = resolved_to_install_packages(&resolve_result.packages, &deps);

            if !json_output {
                output::info(&format!(
                    "Resolved {} packages ({}ms)",
                    packages.len().to_string().bold(),
                    ms
                ));
            }
            (packages, ms, false)
        }
    };

    // Step 3: Download & store (parallel)
    let fetch_start = Instant::now();
    let store = PackageStore::default_location()?;

    let mut to_download = Vec::new();
    let mut cached = 0usize;

    for p in &packages {
        // --force: re-download everything to verify integrity against registry,
        // even if the store already has it. The store's extract-to-temp + atomic
        // rename handles the case where the existing entry is valid.
        if !force && store.has_package(&p.name, &p.version) {
            cached += 1;
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
    if !to_download.is_empty() {
        let overall = ProgressBar::new(to_download.len() as u64);
        overall.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} Downloading [{bar:30.cyan/dim}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("━╸─"),
        );
        overall.enable_steady_tick(std::time::Duration::from_millis(80));

        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS));
        let mut handles = Vec::new();

        for p in to_download {
            let sem = semaphore.clone();
            let client = arc_client.clone();
            let store_ref = store.clone();
            let overall = overall.clone();

            handles.push(tokio::spawn(async move {
                let _permit = sem
                    .acquire()
                    .await
                    .map_err(|_| LpmError::Registry("download semaphore closed".into()))?;

                overall.set_message(format!("{}@{}", p.name, p.version));

                // Download tarball to temp file (bounded-memory spool pipeline).
                // Hash is computed during download — no second pass needed.
                // On 404, invalidate stale metadata cache so the next `lpm install`
                // re-resolves with fresh metadata.
                let downloaded = match fetch_tarball_to_file(
                    &client,
                    &p.name,
                    &p.version,
                    p.is_lpm,
                    p.tarball_url.as_deref(),
                )
                .await
                {
                    Ok(result) => result,
                    Err(LpmError::NotFound(_)) => {
                        // Invalidate stale metadata cache
                        client.invalidate_metadata_cache(&p.name);
                        let lock_path = std::path::Path::new("lpm.lock");
                        if lock_path.exists() {
                            let _ = std::fs::remove_file(lock_path);
                        }
                        let lockb_path = std::path::Path::new("lpm.lockb");
                        if lockb_path.exists() {
                            let _ = std::fs::remove_file(lockb_path);
                        }
                        return Err(LpmError::NotFound(format!(
                            "{}@{} tarball not found (possibly unpublished). \
                                 Cache cleared — run `lpm install` again to re-resolve.",
                            p.name, p.version
                        )));
                    }
                    Err(e) => return Err(e),
                };

                let computed_sri = downloaded.sri.clone();

                // Verify integrity before storing — prevents tampered tarballs
                // from entering the global store. The SHA-512 SRI hash was computed
                // during download (streaming), so most verifications are a string
                // comparison. For non-sha512 algorithms (sha256), we stream-verify
                // from the temp file in 64KB chunks — never buffers the tarball in memory.
                if let Some(ref integrity) = p.integrity {
                    if computed_sri != *integrity {
                        // Different algorithm or hash mismatch — verify from file (bounded-memory)
                        if let Err(e) =
                            lpm_extractor::verify_integrity_file(downloaded.file.path(), integrity)
                        {
                            return Err(LpmError::Registry(format!(
                                "integrity verification failed for {}@{}: {e}",
                                p.name, p.version
                            )));
                        }
                    }
                } else {
                    tracing::warn!(
                        "no integrity hash for {}@{} — skipping verification",
                        p.name,
                        p.version
                    );
                }

                // Extract from temp file — bounded memory, tarball never in heap
                store_ref.store_package_from_file(
                    &p.name,
                    &p.version,
                    downloaded.file.path(),
                    &computed_sri,
                )?;

                overall.inc(1);
                // Return (name, version, computed_sri) so integrity can be persisted in lockfile
                Ok::<(String, String, String), LpmError>((
                    p.name.clone(),
                    p.version.clone(),
                    computed_sri,
                ))
            }));
        }

        // Collect computed integrity hashes from downloads
        let mut integrity_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for handle in handles {
            let (name, version, sri) = handle
                .await
                .map_err(|e| LpmError::Registry(format!("download task panicked: {e}")))??;
            integrity_map.insert(format!("{name}@{version}"), sri);
        }

        // Update packages with computed integrity hashes (for lockfile persistence)
        for p in &mut packages {
            let key = format!("{}@{}", p.name, p.version);
            if let Some(sri) = integrity_map.get(&key) {
                p.integrity = Some(sri.clone());
            }
        }

        overall.finish_and_clear();
    }

    let fetch_ms = fetch_start.elapsed().as_millis();
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

    // Step 4: Build link targets
    let link_targets: Vec<LinkTarget> = packages
        .iter()
        .map(|p| LinkTarget {
            name: p.name.clone(),
            version: p.version.clone(),
            store_path: store.package_dir(&p.name, &p.version),
            dependencies: p.dependencies.clone(),
            is_direct: p.is_direct,
        })
        .collect();

    // Step 5: Link into node_modules
    let link_start = Instant::now();
    let spinner = make_spinner("Linking node_modules...");

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
    let blocked_capture = crate::build_state::capture_blocked_set_after_install(
        project_dir,
        &store,
        &installed_with_integrity,
        &policy,
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
            let all_pkgs: Vec<(String, String)> = packages
                .iter()
                .map(|p| (p.name.clone(), p.version.clone()))
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

            let warnings = crate::intelligence::check_install_quality(
                &lpm_registry::RegistryClient::new()
                    .with_base_url(
                        std::env::var("LPM_REGISTRY_URL")
                            .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
                    )
                    .with_token(
                        crate::auth::get_token(
                            &std::env::var("LPM_REGISTRY_URL")
                                .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
                        )
                        .unwrap_or_default(),
                    ),
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
                crate::security_check::post_install_security_summary(
                    &lpm_registry::RegistryClient::new()
                        .with_base_url(
                            std::env::var("LPM_REGISTRY_URL")
                                .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
                        )
                        .with_token(
                            crate::auth::get_token(
                                &std::env::var("LPM_REGISTRY_URL").unwrap_or_else(|_| {
                                    lpm_common::DEFAULT_REGISTRY_URL.to_string()
                                }),
                            )
                            .unwrap_or_default(),
                        ),
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

            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                source: Some(p.source.clone()),
                integrity: p.integrity.clone(),
                dependencies: dep_strings,
            });
        }

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

    // Step 10: Auto-build trusted packages (after lockfile is written)
    // Triggers when: --auto-build flag, lpm.scripts.autoBuild config, or ALL scripted packages are trusted
    let config_auto_build = read_auto_build_config(project_dir);
    let all_pkgs_for_build: Vec<(String, String)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone()))
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
    if let (Ok(pkg), Ok(lock)) = (
        std::fs::read_to_string(project_dir.join("package.json")),
        std::fs::read_to_string(project_dir.join("lpm.lock")),
    ) {
        let hash = crate::install_state::compute_install_hash(&pkg, &lock);
        let hash_dir = project_dir.join(".lpm");
        let _ = std::fs::create_dir_all(&hash_dir);
        let _ = std::fs::write(hash_dir.join("install-hash"), &hash);
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

// Phase 34.1: is_install_up_to_date() moved to crate::install_state::check_install_state()

/// Try to use the lockfile as a fast path.
///
/// Returns `Some(packages)` if the lockfile exists AND every declared dependency
/// in package.json has a matching entry in the lockfile. Otherwise returns `None`
/// to signal that fresh resolution is needed.
fn try_lockfile_fast_path(
    lockfile_path: &Path,
    deps: &HashMap<String, String>,
) -> Option<Vec<InstallPackage>> {
    if !lpm_lockfile::Lockfile::exists(lockfile_path) {
        return None;
    }

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

    // Verify every declared dep has a lockfile entry
    for dep_name in deps.keys() {
        if lockfile.find_package(dep_name).is_none() {
            tracing::debug!("lockfile miss: {dep_name} not found, re-resolving");
            return None;
        }
    }

    // Build the direct dep set for is_direct marking
    let direct_deps: std::collections::HashSet<&str> = deps.keys().map(|s| s.as_str()).collect();

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

            InstallPackage {
                name: lp.name.clone(),
                version: lp.version.clone(),
                source: lp
                    .source
                    .clone()
                    .unwrap_or_else(|| "registry+https://registry.npmjs.org".to_string()),
                dependencies,
                is_direct: direct_deps.contains(lp.name.as_str()),
                is_lpm,
                integrity: lp.integrity.clone(),
                tarball_url: None, // Lockfile doesn't store URLs — fetched on demand
            }
        })
        .collect();

    Some(packages)
}

/// Convert resolver output to InstallPackage list.
fn resolved_to_install_packages(
    resolved: &[ResolvedPackage],
    deps: &HashMap<String, String>,
) -> Vec<InstallPackage> {
    resolved
        .iter()
        .map(|r| {
            let name = r.package.canonical_name();
            let is_lpm = r.package.is_lpm();
            let source = if is_lpm {
                "registry+https://lpm.dev".to_string()
            } else {
                "registry+https://registry.npmjs.org".to_string()
            };

            InstallPackage {
                name: name.clone(),
                version: r.version.to_string(),
                source,
                dependencies: r.dependencies.clone(),
                is_direct: deps.contains_key(&name),
                is_lpm,
                integrity: r.integrity.clone(),
                tarball_url: r.tarball_url.clone(),
            }
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
            is_direct: p.is_direct,
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
            let all_pkgs: Vec<(String, String)> = packages
                .iter()
                .map(|p| (p.name.clone(), p.version.clone()))
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
            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                source: Some(p.source.clone()),
                integrity: p.integrity.clone(),
                dependencies: dep_strings,
            });
        }
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

/// Fetch tarball + compute SHA-512 hash in one pass.
/// Returns (tarball_bytes, "sha512-{base64}") so the caller can verify
/// integrity without re-hashing the entire buffer.
/// Download a tarball to a temp file on disk (bounded-memory spool pipeline).
///
/// Returns `DownloadedTarball` — the tarball is on disk, never fully in memory.
/// The SRI hash was computed as chunks arrived during download.
async fn fetch_tarball_to_file(
    client: &Arc<RegistryClient>,
    name: &str,
    version: &str,
    is_lpm: bool,
    cached_url: Option<&str>,
) -> Result<lpm_registry::DownloadedTarball, LpmError> {
    // Use the tarball URL from resolution if available — avoids re-fetching
    // metadata just to get the URL (saves one HTTP round-trip per package
    // on the lockfile-miss path).
    let url = if let Some(url) = cached_url {
        url.to_string()
    } else if is_lpm {
        let pkg =
            lpm_common::PackageName::parse(name).map_err(|e| LpmError::Registry(e.to_string()))?;
        let metadata = client.get_package_metadata(&pkg).await?;
        let ver_meta = metadata
            .version(version)
            .ok_or_else(|| LpmError::NotFound(format!("{name}@{version} not found in metadata")))?;
        ver_meta
            .tarball_url()
            .ok_or_else(|| LpmError::NotFound(format!("no tarball URL for {name}@{version}")))?
            .to_string()
    } else {
        let metadata = client.get_npm_package_metadata(name).await?;
        let ver_meta = metadata
            .version(version)
            .ok_or_else(|| LpmError::NotFound(format!("{name}@{version} not found in metadata")))?;
        ver_meta
            .tarball_url()
            .ok_or_else(|| LpmError::NotFound(format!("no tarball URL for {name}@{version}")))?
            .to_string()
    };
    client.download_tarball_to_file(&url).await
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

    // 3. Multi-member preview line (informational only — Phase 2 ships
    //    without an interactive y/N prompt; the JSON output mode and the
    //    `--fail-if-no-match` flag give CI users the safety net they need).
    if targets.multi_member && !json_output {
        output::info(&format!(
            "Adding {} package(s) to {} workspace member(s):",
            packages.len(),
            targets.member_manifests.len(),
        ));
        for path in &targets.member_manifests {
            let label = path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            println!("  {}", label.dimmed());
        }
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

/// Read `lpm.scripts.autoBuild` from package.json.
fn read_auto_build_config(project_dir: &Path) -> bool {
    let pkg_json_path = project_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };

    parsed
        .get("lpm")
        .and_then(|l| l.get("scripts"))
        .and_then(|s| s.get("autoBuild"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_build_trigger_enables_when_any_current_source_requests_it() {
        assert!(should_auto_build(true, false, false));
        assert!(should_auto_build(false, true, false));
        assert!(should_auto_build(false, false, true));
        assert!(!should_auto_build(false, false, false));
    }

    #[test]
    fn read_auto_build_config_reads_nested_lpm_flag() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"lpm":{"scripts":{"autoBuild":true}}}"#,
        )
        .unwrap();

        assert!(read_auto_build_config(dir.path()));
    }

    #[test]
    fn read_auto_build_config_defaults_false_for_missing_or_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();
        assert!(!read_auto_build_config(dir.path()));

        std::fs::write(dir.path().join("package.json"), "{not json").unwrap();
        assert!(!read_auto_build_config(dir.path()));
    }

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
}
