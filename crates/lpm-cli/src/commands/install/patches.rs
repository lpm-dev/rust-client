use super::*;
use lpm_linker::{LinkResult, MaterializedPackage};

pub(super) fn applied_patch_to_state_hit(
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

/// Persist
/// `.lpm/patch-state.json` with the right `applied` trace for the
/// install run. Three cases:
///
/// 1. **Work happened this run** (any apply result has non-zero file
///    counts) → capture a fresh trace from the run results.
/// 2. **No work happened this run** (idempotent rerun: every file
///    already had the expected post-patch bytes) AND a prior state
///    file exists → preserve the prior state's `applied` list so
///    `lpm graph --why` doesn't go blind. Mirror of /// `OverridesState::capture_preserving_applied`.
/// 3. **No work happened this run AND no prior state** (rare edge:
///    user pre-staged patched bytes manually) → record what we know
///    (the run results, even if all-zero — the next non-idempotent
///    run will fix this).
///
/// Previously: case (2) overwrote the state file with all-zero results,
/// which made the file count visible in `lpm graph --why` decay to
/// zero on every idempotent rerun.
pub(super) fn persist_patch_state(
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

/// Build the JSON
/// `applied_patches` array shape from a slice of engine results.
/// Filtering to `touched_anything()` is done by the caller — this
/// helper formats whatever it's given.
pub(super) fn applied_patches_to_json(
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

/// Emit a fingerprint field for JSON output.
///
/// Empty feature sets are represented as `null` instead of the SHA-256
/// of empty input so consumers don't need to recognize a sentinel hash
/// to distinguish "no entries" from "some concrete set".
pub(super) fn fingerprint_json_value(
    count: usize,
    fingerprint: impl Into<String>,
) -> serde_json::Value {
    if count == 0 {
        serde_json::Value::Null
    } else {
        serde_json::json!(fingerprint.into())
    }
}

///
///
/// Run unconditionally after the linker (and the workspace-member
/// linker pass). For each entry in `lpm.patchedDependencies`, find every
/// physical destination of the target package via `link_result.materialized`
/// and apply the patch there. Drift, fuzzy hunks, missing files, and
/// internal-file modification attempts are all hard install errors.
///
/// compute the
/// per-target patch fingerprint map that the link pipeline folds into
/// each `LinkTarget.patch_fingerprint` (and downstream into v2's
/// [`lpm_store::v2::GraphKeyInputs::patch_fingerprint`]).
///
/// Without this, two projects with the same dep graph share a single
/// `<store>/v2/links/<key>/...` materialization, and project A's
/// `apply_patch` mutation propagates into project B's view via the
/// shared link entry. The fix is to fold patch identity into the
/// graph key so a patched install lands in its own dir.
///
/// **Hash inputs:** `sha256(patch_bytes || 0x00 || originalIntegrity || 0x01)`,
/// truncated to 16 hex chars and prefixed `p-`. Content-derived so:
/// - Two projects applying the **same** patch text against the same
///   pinned baseline collide on the same fingerprint and share a
///   single link entry (the cheap, correct case).
/// - Any edit to the patch text — or rotation of `originalIntegrity` —
///   splits into a fresh entry. Old patched bytes never leak forward.
///
/// **Hot-path cost:** zero allocation when `patches.is_empty()`. One
/// `read` + one `Sha256::finalize` per declared patch otherwise.
/// Surfacing missing-file errors here (rather than deferring to the
/// later `apply_patches_for_install`) keeps the install trace pointed
/// at the right cause when a patch file goes missing.
pub(super) fn compute_patch_fingerprints(
    patches: &HashMap<String, PatchedDependencyEntry>,
    project_dir: &Path,
) -> Result<HashMap<(String, String), String>, LpmError> {
    use sha2::{Digest, Sha256};

    if patches.is_empty() {
        return Ok(HashMap::new());
    }

    let mut out = HashMap::with_capacity(patches.len());
    let mut sorted_keys: Vec<&String> = patches.keys().collect();
    sorted_keys.sort();

    for key in sorted_keys {
        let entry = &patches[key];
        let (name, version) = patch_engine::parse_patch_key(key)?;
        let patch_path = project_dir.join(&entry.path);
        let patch_bytes = std::fs::read(&patch_path).map_err(|e| {
            LpmError::Script(format!(
                "patch file {} declared in lpm.patchedDependencies[{key}] cannot be read: {e}",
                entry.path
            ))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(&patch_bytes);
        hasher.update(b"\x00");
        hasher.update(entry.original_integrity.as_bytes());
        hasher.update(b"\x01");
        let digest = hasher.finalize();
        let short = &hex::encode(digest)[..16];
        out.insert((name, version), format!("p-{short}"));
    }
    Ok(out)
}

/// Both online (`run_with_options`) and offline (`run_link_and_finish`)
/// install paths call this exact function — there is no parallel apply
/// logic to keep in sync.
///
/// Returns the per-entry [`patch_engine::AppliedPatch`] vector. The
/// caller threads it into the JSON output and the `.lpm/patch-state.json`
/// persist step.
pub(super) fn apply_patches_for_install(
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
        // hoisted root, nested under hoisted parent, hoisted-nested
        // fallback at `<project>/.lpm/hoisted/nested/`) so we never
        // have to reverse-engineer the layout.
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
