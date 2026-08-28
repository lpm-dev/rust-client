//!
//!
//! Two-step workflow:
//!
//! 1. `lpm patch <name>@<version>` extracts a clean copy of the store
//!    package to a unique staging dir under the OS temp root, prints
//!    the path, and writes a breadcrumb file (`.lpm-patch.json`) so
//!    the second step can recover `(name, version, store_path)`.
//!
//! 2. The user edits files in the staging package directory.
//!
//! 3. `lpm patch-commit <staging_dir>` reads the breadcrumb, generates
//!    a unified diff against the store baseline, writes
//!    `<project>/patches/<key>.patch`, updates `package.json` with the
//!    new `lpm.patchedDependencies` entry, and cleans up the staging
//!    directory.
//!
//! Patches travel with the repo. The next `lpm install` automatically
//! re-applies them after linking.

use crate::install_ui;
use crate::patch_engine::{
    GeneratedPatch, PatchSelector, STAGING_BREADCRUMB_FILE, copy_store_to_staging, generate_patch,
    parse_patch_selector, resolve_patch_selector,
};
use lpm_common::LpmError;
use lpm_lockfile::{Lockfile, LockfilePatch};
use lpm_store::{
    find_installed_package_baseline_by_identity, find_unique_installed_package_baseline,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct PatchTarget {
    name: String,
    version: String,
    integrity: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchBreadcrumb {
    name: String,
    version: String,
    key: String,
    integrity: String,
}

// ── lpm patch ────────────────────────────────────────────────────────

/// `lpm patch <selector>` — extract a store copy to a staging dir.
///
/// `<selector>` accepts a bare name (`lodash`), an exact pin
/// (`lodash@4.17.21`), or a semver range (`lodash@^4.0.0`). Bare names
/// and ranges resolve to an exact pin against the project lockfile
/// BEFORE entering the store lock scope; the persisted-key path that
/// runs under the lock always sees an exact `(name, version)`.
///
/// **Why selector resolution runs outside the lock:** the lockfile
/// read is project-scoped and unrelated to the global store. Holding
/// the store lock during a "your selector matches three packages"
/// error print would block other `lpm patch` / `lpm install`
/// invocations for no reason. The structural seam — parse and
/// resolve happen in this function, lock and staging happen in
/// `run_patch_inner` — is the contract the unit tests exercise.
pub async fn run_patch(project_dir: &Path, input: &str, json_output: bool) -> Result<(), LpmError> {
    let project_dir = resolve_patch_project_root(project_dir)?;
    let selector = parse_patch_selector(input)?;
    let target = resolve_patch_target(&project_dir, &selector)?;
    let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
    lpm_common::with_shared_lock_async(lock_path, run_patch_inner(target, json_output)).await
}

/// Read the project lockfile, or surface an actionable error if the
/// project hasn't been installed yet. Bare-name / range selectors
/// REQUIRE a lockfile — exact pins do not (the legacy workflow tests
/// exercise `lpm patch <name>@<exact>` on projects with no lockfile,
/// and that capability must be preserved).
fn read_lockfile_for_patch_selector(project_dir: &Path) -> Result<Lockfile, LpmError> {
    match Lockfile::read_for_project(project_dir) {
        Ok(project) => Ok(project.lockfile),
        Err(lpm_lockfile::LockfileError::NotFound(_)) => Err(LpmError::Script(
            "bare-name and semver-range selectors require a project lockfile. \
             Run `lpm install` first, or pass an exact pin like \
             `lpm patch <name>@<version>`."
                .into(),
        )),
        Err(error) => Err(LpmError::Script(format!(
            "failed to read project lockfile: {error}"
        ))),
    }
}

fn resolve_patch_project_root(project_dir: &Path) -> Result<PathBuf, LpmError> {
    if project_dir.join("package.json").is_file() {
        return Ok(project_dir.to_path_buf());
    }
    lpm_workspace::find_project_root(project_dir).ok_or_else(|| {
        LpmError::Script(format!(
            "no package.json found in {} or its ancestors",
            project_dir.display()
        ))
    })
}

fn patch_commit_command(staging_path: &Path) -> String {
    let raw = staging_path.display().to_string();
    let quoted = shlex::try_quote(&raw)
        .map(|value| value.into_owned())
        .unwrap_or(raw);
    format!("lpm patch-commit {quoted}")
}

fn validate_owned_staging_directory(staging_dir: &Path) -> Result<PathBuf, LpmError> {
    let metadata = std::fs::symlink_metadata(staging_dir).map_err(|error| {
        LpmError::Script(format!(
            "staging directory {} is unavailable: {error}",
            staging_dir.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LpmError::Script(format!(
            "staging directory {} is not a real directory",
            staging_dir.display()
        )));
    }
    let canonical = staging_dir.canonicalize().map_err(LpmError::Io)?;
    let temp_root = std::env::temp_dir().canonicalize().map_err(LpmError::Io)?;
    let owned_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("lpm-patch-"));
    if canonical.parent() != Some(temp_root.as_path()) || !owned_name {
        return Err(LpmError::Script(format!(
            "refusing staging directory {} because it is not an lpm-owned direct child of {}",
            staging_dir.display(),
            temp_root.display()
        )));
    }
    Ok(canonical)
}

fn patch_file_relative_path(name: &str, key: &str) -> String {
    if !name.contains('/') && key.len() <= 180 {
        return format!("patches/{key}.patch");
    }
    let readable: String = key
        .chars()
        .map(|character| match character {
            '/' => '+',
            character if character.is_ascii_alphanumeric() => character,
            '@' | '.' | '_' | '-' | '+' => character,
            _ => '-',
        })
        .take(120)
        .collect();
    let digest = crate::patch_fs::sha256_bytes(key.as_bytes());
    format!("patches/{readable}-{}.patch", &digest["sha256-".len()..])
}

fn resolve_patch_target(
    project_dir: &Path,
    selector: &PatchSelector,
) -> Result<PatchTarget, LpmError> {
    match selector {
        PatchSelector::Exact { name, version } => {
            let lockfile = match Lockfile::read_for_project(project_dir) {
                Ok(project) => Some(project.lockfile),
                Err(lpm_lockfile::LockfileError::NotFound(_)) => None,
                Err(error) => {
                    return Err(LpmError::Script(format!(
                        "failed to read project lockfile: {error}"
                    )));
                }
            };
            let integrity = lockfile
                .as_ref()
                .map(|lockfile| locked_integrity_for_coordinates(lockfile, name, version))
                .transpose()?
                .flatten();
            Ok(PatchTarget {
                name: name.clone(),
                version: version.clone(),
                integrity,
            })
        }
        PatchSelector::BareName(_) | PatchSelector::Range { .. } => {
            let lockfile = read_lockfile_for_patch_selector(project_dir)?;
            let (name, version) = resolve_patch_selector(&lockfile, selector)?;
            let integrity = locked_integrity_for_coordinates(&lockfile, &name, &version)?;
            Ok(PatchTarget {
                name,
                version,
                integrity,
            })
        }
    }
}

fn locked_integrity_for_coordinates(
    lockfile: &Lockfile,
    name: &str,
    version: &str,
) -> Result<Option<String>, LpmError> {
    let mut identities = BTreeSet::new();
    for package in &lockfile.packages {
        if package.name == name && package.version == version {
            identities.insert((package.source.clone(), package.integrity.clone()));
        }
    }
    match identities.len() {
        0 => Ok(None),
        1 => Ok(identities.pop_first().and_then(|(_, integrity)| integrity)),
        _ => Err(LpmError::Script(format!(
            "this project has multiple source identities for `{name}@{version}`; pin it to a single source before creating a patch"
        ))),
    }
}

async fn run_patch_inner(target: PatchTarget, json_output: bool) -> Result<(), LpmError> {
    let PatchTarget {
        name,
        version,
        integrity,
    } = target;
    // Lookup goes
    // through `find_installed_package_baseline`, which prefers the
    // default v2, then experimental v3, and falls back to v1.
    // Pre-fix this called `store.has_package(...)` (v1-only), which
    // always returned false under virtual stores → "not in the global store".
    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let baseline = match integrity.as_deref() {
        Some(integrity) => {
            find_installed_package_baseline_by_identity(&lpm_root, &name, &version, Some(integrity))
        }
        None => find_unique_installed_package_baseline(&lpm_root, &name, &version),
    }?
    .ok_or_else(|| {
        LpmError::Script(format!(
            "{name}@{version} with the selected source identity is not in the global store. \
                 Run `lpm install {name}@{version}` first."
        ))
    })?;
    // Seed the staging copy from
    // the PRISTINE bytes — the virtual-store object projection, or the v1 store
    // dir (which v1 patches never mutate). Reading `package_dir` on
    // an already-patched v2 link entry would seed the staging dir
    // with previously-applied edits, defeating the workflow.
    let store_path = baseline.pristine_dir;

    // Build a unique staging directory under the OS temp root. We
    // explicitly do NOT use `TempDir` (which would auto-delete on
    // Drop) — the staging dir must outlive this process so the user
    // can edit files in it before running `lpm patch-commit`.
    let staging_root = tempfile::Builder::new()
        .prefix("lpm-patch-")
        .tempdir_in(std::env::temp_dir())
        .map_err(LpmError::Io)?;
    let staging_path = staging_root.path().to_path_buf();

    let dest = staging_path.join("node_modules").join(&name);
    copy_store_to_staging(&store_path, &dest)?;

    // Write the breadcrumb. patch-commit reads this to recover the
    // identity without re-parsing the staging path. **The `key` field
    // is always the resolved exact pin**, never the raw user input —
    // so a user who typed `lpm patch lodash@^4.0.0` still produces a
    // breadcrumb with `key: "lodash@4.17.21"` and `lpm patch-commit`
    // writes `patches/lodash@4.17.21.patch`.
    let resolved_key = format!("{name}@{version}");
    let breadcrumb = json!({
        "name": name,
        "version": version,
        "key": resolved_key,
        "integrity": baseline.integrity,
    });
    std::fs::write(
        staging_path.join(STAGING_BREADCRUMB_FILE),
        serde_json::to_string_pretty(&breadcrumb).unwrap(),
    )
    .map_err(LpmError::Io)?;
    let staging_path = staging_root.keep();

    if json_output {
        let payload = json!({
            "success": true,
            "name": name,
            "version": version,
            "key": resolved_key,
            "staging_dir": staging_path.display().to_string(),
            "package_dir": dest.display().to_string(),
            "next_steps": [
                {
                    "description": "Commit the patch after editing package_dir",
                    "command": patch_commit_command(&staging_path),
                    "args": ["lpm", "patch-commit", staging_path.display().to_string()],
                },
            ],
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
    } else {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Extracting pristine store entry for {}",
            install_ui::yellow(&resolved_key)
        ));
        let label_width = "staging:".len();
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "    {} {}",
            install_ui::dim(&format!("{:<label_width$}", "source:")),
            install_ui::dim(&store_path.display().to_string())
        ));
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "    {} {}",
            install_ui::dim(&format!("{:<label_width$}", "staging:")),
            install_ui::dim(&dest.display().to_string())
        ));
        install_ui::detail("");
        install_ui::done("Ready · edit files in the staging directory, then run:");
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "  {}",
            install_ui::yellow(&patch_commit_command(&staging_path))
        ));
    }
    Ok(())
}

// ── lpm patch-commit ─────────────────────────────────────────────────

/// `lpm patch-commit <staging_dir>` — finalize a patch into the project.
pub async fn run_patch_commit(
    project_dir: &Path,
    staging_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let project_dir = resolve_patch_project_root(project_dir)?;
    let lock_path = lpm_common::LpmRoot::from_env()?.store_lock();
    lpm_common::with_shared_lock_async(
        lock_path,
        run_patch_commit_inner(&project_dir, staging_dir, json_output),
    )
    .await
}

async fn run_patch_commit_inner(
    project_dir: &Path,
    staging_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let staging_dir = validate_owned_staging_directory(staging_dir)?;
    let staging_root = crate::patch_fs::SafeRoot::open(&staging_dir)?;
    let breadcrumb_bytes = staging_root
        .read_regular_file(
            Path::new(STAGING_BREADCRUMB_FILE),
            lpm_common::STATE_FILE_SIZE_CAP_BYTES,
        )
        .map_err(|error| {
            LpmError::Script(format!(
                "{staging_dir:?} is not an lpm-patch staging dir (no .lpm-patch.json): {error}"
            ))
        })?;
    let breadcrumb: PatchBreadcrumb = serde_json::from_slice(&breadcrumb_bytes).map_err(|e| {
        LpmError::Script(format!(
            "staging breadcrumb at {:?} is malformed: {e}",
            staging_dir.join(STAGING_BREADCRUMB_FILE)
        ))
    })?;
    Lockfile::validate_package_name_and_version(&breadcrumb.name, &breadcrumb.version)
        .map_err(|error| LpmError::Script(format!("invalid staging identity: {error}")))?;
    let canonical_version = lpm_semver::Version::parse(&breadcrumb.version)
        .map_err(|error| LpmError::Script(format!("invalid staging version: {error}")))?
        .to_string();
    if canonical_version != breadcrumb.version {
        return Err(LpmError::Script(format!(
            "staging version {:?} is not canonical; expected {canonical_version:?}",
            breadcrumb.version
        )));
    }
    let expected_key = format!("{}@{}", breadcrumb.name, breadcrumb.version);
    if breadcrumb.key != expected_key {
        return Err(LpmError::Script(format!(
            "staging breadcrumb key {:?} does not match identity {expected_key:?}",
            breadcrumb.key
        )));
    }
    let name = breadcrumb.name.as_str();
    let version = breadcrumb.version.as_str();
    let key = breadcrumb.key.as_str();

    let lpm_root = lpm_common::LpmRoot::from_env()?;
    let baseline = find_installed_package_baseline_by_identity(
        &lpm_root,
        name,
        version,
        Some(&breadcrumb.integrity),
    )?
    .ok_or_else(|| {
        LpmError::Script(format!(
            "the store baseline for {name}@{version} changed since this staging directory was created; preserve your edits and run `lpm patch {name}@{version}` again"
        ))
    })?;
    let store_path = baseline.pristine_dir.clone();

    let edited_relative = Path::new("node_modules").join(name);
    staging_root.open_directory(&edited_relative)?;
    let edited_dir = staging_dir.join(&edited_relative);

    // 3. Generate the unified diff.
    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Generating patch for {}",
            install_ui::yellow(key)
        ));
    }
    let generated: GeneratedPatch = generate_patch(&store_path, &edited_dir)?;
    // Check binary files BEFORE the empty check — a staging dir whose
    // ONLY change is a binary edit produces an empty `diff` text but
    // a non-empty `binary_files_differ` list. Reporting "no changes"
    // would be misleading; the user did make a change, just one we
    // don't accept.
    if !generated.binary_files_differ.is_empty() {
        return Err(LpmError::Script(format!(
            "binary files differ ({:?}); patches must be text-only — \
             remove the binary edits before committing",
            generated.binary_files_differ
        )));
    }
    if generated.diff.is_empty() {
        return Err(LpmError::Script(format!(
            "no changes detected in {edited_dir:?} — patch-commit aborted"
        )));
    }

    // 4. Original integrity comes from the v2 link sidecar
    // (`meta.source_sri`) or v1's `.integrity` sentinel — both
    // resolved in step 2's lookup, so no second probe needed.
    let integrity = baseline.integrity;

    let patch_file_rel = patch_file_relative_path(name, key);
    let patch_file_relative = PathBuf::from(&patch_file_rel);
    let patches_dir = project_dir.join("patches");
    let patches_dir_existed = std::fs::symlink_metadata(&patches_dir)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink());
    let patch_file_abs = project_dir.join(&patch_file_rel);
    let patch_sha256 = crate::patch_fs::sha256_bytes(generated.diff.as_bytes());
    let project_dirs = [project_dir.to_path_buf()];
    let mutation =
        crate::commands::install::workspace_lockfile::scope_workspace_mutation_if_present(
            project_dir,
            &project_dirs,
            async {
                let pkg_json_path = project_dir.join("package.json");
                let manifest_plan =
                    plan_package_json_patch_update(project_dir, key, &patch_file_rel, &integrity)?;
                let lockfile_path =
                    crate::commands::install::workspace_lockfile::active_lockfile_path(project_dir);
                let lockfile_binary_path = lockfile_path.with_extension("lockb");
                let gitattributes_path = lockfile_path.with_file_name(".gitattributes");
                let install_hash_path = project_dir.join(".lpm").join("install-hash");
                let mut optional_paths = Vec::with_capacity(5);
                optional_paths.push(patch_file_abs.clone());
                optional_paths.push(lockfile_path);
                optional_paths.push(lockfile_binary_path);
                optional_paths.push(gitattributes_path);
                if let Some(obsolete) = manifest_plan.obsolete_patch.as_ref() {
                    optional_paths.push(project_dir.join(obsolete));
                }
                let optional: Vec<&Path> = optional_paths.iter().map(PathBuf::as_path).collect();
                let transaction =
                    crate::manifest_tx::ManifestTransaction::snapshot_install_state_if_unchanged(
                        &[(
                            pkg_json_path.as_path(),
                            manifest_plan.manifest_bytes.as_slice(),
                        )],
                        &optional,
                        &[install_hash_path.as_path()],
                    )?;

                let project_root = crate::patch_fs::SafeRoot::open(project_dir)?;
                project_root.write_regular_file(
                    &patch_file_relative,
                    generated.diff.as_bytes(),
                    None,
                )?;
                write_package_json_value(project_dir, &manifest_plan.manifest)?;
                let lockfile_updated = upsert_lockfile_patch_record(
                    project_dir,
                    key,
                    &patch_file_rel,
                    &patch_sha256,
                    &integrity,
                )?;
                if let Some(obsolete) = manifest_plan.obsolete_patch {
                    project_root.remove_regular_file(&obsolete)?;
                }
                crate::commands::install::workspace_lockfile::commit_manifest_transaction(
                    transaction,
                );
                Ok(lockfile_updated)
            },
        )
        .await;
    if mutation.is_err() && !patches_dir_existed {
        let _ = std::fs::remove_dir(&patches_dir);
    }
    let lockfile_updated = mutation?;

    // 7. Clean up the staging dir on success. Best-effort — we don't
    //    fail the command if cleanup hiccups.
    let _ = std::fs::remove_dir_all(&staging_dir);

    if json_output {
        let payload = json!({
            "success": true,
            "name": name,
            "version": version,
            "key": key,
            "patch_file": patch_file_rel,
            "files_changed": generated.files_changed,
            "insertions": generated.insertions,
            "deletions": generated.deletions,
            "original_integrity": integrity,
            "lockfile_updated": lockfile_updated,
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
    } else {
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Wrote {}",
            install_ui::dim(&patch_file_rel)
        ));
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Updated {}",
            install_ui::cyan("package.json › lpm.patchedDependencies")
        ));
        if lockfile_updated {
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Updated {}",
                install_ui::dim("lpm.lock")
            ));
        }
        install_ui::detail("");
        install_ui::done("Done · patch registered for future installs");
    }

    Ok(())
}

// ── lpm patch-remove ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct PatchRemoval {
    key: String,
    patch_file: String,
    deleted_patch_file: bool,
    retained_reason: Option<String>,
}

/// `lpm patch-remove <selector...>` — unregister local patches.
pub async fn run_patch_remove(
    project_dir: &Path,
    selectors: &[String],
    dry_run: bool,
    keep_file: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let project_dir = resolve_patch_project_root(project_dir)?;
    let (outcome, lockfile_updated) = if dry_run {
        (
            remove_package_json_patches(&project_dir, selectors, true, keep_file)?,
            false,
        )
    } else {
        let project_dirs = [project_dir.to_path_buf()];
        crate::commands::install::workspace_lockfile::scope_workspace_mutation_if_present(
            &project_dir,
            &project_dirs,
            async {
                let plan =
                    plan_package_json_patch_removal(&project_dir, selectors, false, keep_file)?;
                let pkg_json_path = project_dir.join("package.json");
                let lockfile_path =
                    crate::commands::install::workspace_lockfile::active_lockfile_path(
                        &project_dir,
                    );
                let lockfile_binary_path = lockfile_path.with_extension("lockb");
                let gitattributes_path = lockfile_path.with_file_name(".gitattributes");
                let install_hash_path = project_dir.join(".lpm").join("install-hash");
                let mut optional_paths = Vec::with_capacity(plan.files_to_delete.len() + 3);
                optional_paths.push(lockfile_path);
                optional_paths.push(lockfile_binary_path);
                optional_paths.push(gitattributes_path);
                optional_paths.extend(
                    plan.files_to_delete
                        .keys()
                        .map(|relative| project_dir.join(relative)),
                );
                let optional: Vec<&Path> = optional_paths.iter().map(PathBuf::as_path).collect();
                let transaction =
                    crate::manifest_tx::ManifestTransaction::snapshot_install_state_if_unchanged(
                        &[(pkg_json_path.as_path(), plan.manifest_bytes.as_slice())],
                        &optional,
                        &[install_hash_path.as_path()],
                    )?;
                let outcome = apply_package_json_patch_removal(&project_dir, plan)?;
                let removed_keys = outcome
                    .removed
                    .iter()
                    .map(|removal| removal.key.clone())
                    .collect();
                let lockfile_updated = remove_lockfile_patch_records(&project_dir, &removed_keys)?;
                crate::commands::install::workspace_lockfile::commit_manifest_transaction(
                    transaction,
                );
                Ok((outcome, lockfile_updated))
            },
        )
        .await?
    };

    if json_output {
        let removed: Vec<_> = outcome
            .removed
            .iter()
            .map(|r| {
                json!({
                    "key": r.key,
                    "patch_file": r.patch_file,
                    "deleted_patch_file": r.deleted_patch_file,
                    "retained_reason": r.retained_reason,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "success": true,
                "dry_run": dry_run,
                "keep_file": keep_file,
                "lockfile_updated": lockfile_updated,
                "removed": removed,
            }))
            .unwrap()
        );
    } else {
        let line = if dry_run {
            install_ui::TerminalLine::new("Previewing removal for ")
        } else {
            install_ui::TerminalLine::new("Removing patch registration for ")
        };
        let line = if outcome.removed.len() == 1 {
            line.yellow(&outcome.removed[0].key)
        } else {
            line.field(&format!("{} patch registrations", outcome.removed.len()))
        };
        install_ui::phase_line(line);
        let label_width = "manifest:".len();
        install_ui::detail_line(crate::install_ui::terminal_line!(
            "    {} {}",
            install_ui::dim(&format!("{:<label_width$}", "manifest:")),
            install_ui::dim("package.json")
        ));
        for removal in &outcome.removed {
            install_ui::detail_line(crate::install_ui::terminal_line!(
                "    {} {}",
                install_ui::dim(&format!("{:<label_width$}", "file:")),
                install_ui::dim(&removal.patch_file)
            ));
        }
        install_ui::detail("");
        for removal in &outcome.removed {
            if removal.deleted_patch_file {
                install_ui::done("Deleted patch file");
            } else if let Some(reason) = &removal.retained_reason {
                install_ui::warn_line(crate::install_ui::terminal_line!(
                    "Kept {} {}",
                    install_ui::dim(&removal.patch_file),
                    install_ui::dim(&format!("({reason})"))
                ));
            }
        }
        if lockfile_updated {
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Updated {}",
                install_ui::dim("lpm.lock")
            ));
        }
        if dry_run {
            install_ui::done("Dry run · package.json unchanged");
        } else {
            install_ui::done("Done · re-run lpm install to refresh node_modules");
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PatchRemovalOutcome {
    removed: Vec<PatchRemoval>,
}

struct PatchRemovalPlan {
    outcome: PatchRemovalOutcome,
    manifest: serde_json::Value,
    manifest_bytes: Vec<u8>,
    files_to_delete: BTreeMap<PathBuf, String>,
}

fn remove_package_json_patches(
    project_dir: &Path,
    selectors: &[String],
    dry_run: bool,
    keep_file: bool,
) -> Result<PatchRemovalOutcome, LpmError> {
    let plan = plan_package_json_patch_removal(project_dir, selectors, dry_run, keep_file)?;
    if dry_run {
        Ok(plan.outcome)
    } else {
        apply_package_json_patch_removal(project_dir, plan)
    }
}

fn plan_package_json_patch_removal(
    project_dir: &Path,
    selectors: &[String],
    dry_run: bool,
    keep_file: bool,
) -> Result<PatchRemovalPlan, LpmError> {
    if selectors.is_empty() {
        return Err(LpmError::Script(
            "patch-remove requires at least one selector".into(),
        ));
    }

    let pkg_path = project_dir.join("package.json");
    let project_root = crate::patch_fs::SafeRoot::open(project_dir)?;
    let raw_bytes = project_root
        .read_regular_file(
            Path::new("package.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .map_err(|error| {
            LpmError::Script(format!("package.json at {pkg_path:?} unreadable: {error}"))
        })?;
    let raw = std::str::from_utf8(&raw_bytes)
        .map_err(|_| LpmError::Script("package.json is not valid UTF-8".into()))?;
    let mut value: serde_json::Value = serde_json::from_str(lpm_common::strip_utf8_bom_str(raw))
        .map_err(|e| LpmError::Script(format!("package.json malformed: {e}")))?;

    let patches_obj = value
        .get("lpm")
        .and_then(|l| l.get("patchedDependencies"))
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            LpmError::Script("package.json has no `lpm.patchedDependencies` entries".into())
        })?;

    if patches_obj.is_empty() {
        return Err(LpmError::Script(
            "package.json has no `lpm.patchedDependencies` entries".into(),
        ));
    }

    let mut normalized_paths = BTreeMap::new();
    let mut name_to_keys = BTreeMap::<String, Vec<String>>::new();
    for (key, entry) in patches_obj {
        let raw_path = entry
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                LpmError::Script(format!(
                    "package.json `lpm.patchedDependencies[{key}].path` is missing or not a string"
                ))
            })?;
        normalized_paths.insert(
            key.clone(),
            crate::patch_fs::validate_manifest_patch_path(raw_path)?,
        );
        let (name, _) = crate::patch_engine::parse_patch_key(key)?;
        name_to_keys.entry(name).or_default().push(key.clone());
    }
    for keys in name_to_keys.values_mut() {
        keys.sort();
    }

    let mut requested = BTreeSet::new();
    for selector in selectors {
        requested.insert(resolve_patch_remove_selector(
            selector,
            patches_obj,
            &name_to_keys,
        )?);
    }

    let remaining_file_refs: BTreeSet<&PathBuf> = normalized_paths
        .iter()
        .filter_map(|(key, path)| (!requested.contains(key)).then_some(path))
        .collect();
    let mut removals = Vec::with_capacity(requested.len());
    let mut files_to_delete = BTreeMap::<PathBuf, String>::new();

    for key in &requested {
        let entry = patches_obj.get(key).ok_or_else(|| {
            LpmError::Script(format!(
                "patch entry {key:?} disappeared while planning removal"
            ))
        })?;
        let patch_file = entry
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                LpmError::Script(format!(
                    "package.json `lpm.patchedDependencies[{key}].path` is missing or not a string"
                ))
            })?
            .to_string();
        let normalized_path = &normalized_paths[key];

        let (deleted_patch_file, retained_reason) = if dry_run {
            (false, Some("dry-run".to_string()))
        } else if keep_file {
            (false, Some("keep-file".to_string()))
        } else if remaining_file_refs.contains(normalized_path) {
            (false, Some("still referenced by another patch".to_string()))
        } else {
            if !is_patch_artifact_path(normalized_path) {
                return Err(LpmError::Script(format!(
                    "refusing to delete patch path {patch_file:?} outside the project patches directory; rerun with --keep-file to remove only the manifest entry"
                )));
            }
            if project_root.regular_file_exists(normalized_path)? {
                files_to_delete
                    .entry(normalized_path.clone())
                    .or_insert_with(|| patch_file.clone());
                (true, None)
            } else {
                (false, Some("file already missing".to_string()))
            }
        };

        removals.push(PatchRemoval {
            key: key.clone(),
            patch_file,
            deleted_patch_file,
            retained_reason,
        });
    }

    if !dry_run {
        remove_patch_entries_from_value(&mut value, &requested)?;
    }

    Ok(PatchRemovalPlan {
        outcome: PatchRemovalOutcome { removed: removals },
        manifest: value,
        manifest_bytes: raw_bytes,
        files_to_delete,
    })
}

fn apply_package_json_patch_removal(
    project_dir: &Path,
    plan: PatchRemovalPlan,
) -> Result<PatchRemovalOutcome, LpmError> {
    let project_root = crate::patch_fs::SafeRoot::open(project_dir)?;
    let current_manifest = project_root.read_regular_file(
        Path::new("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    )?;
    if current_manifest != plan.manifest_bytes {
        return Err(LpmError::Script(
            "package.json changed after patch removal was planned; retry the command".into(),
        ));
    }
    write_package_json_value(project_dir, &plan.manifest)?;

    let mut delete_errors = Vec::new();
    for (relative, raw) in plan.files_to_delete {
        if let Err(error) = project_root.remove_regular_file(&relative) {
            delete_errors.push(format!("{raw}: {error}"));
        }
    }
    if !delete_errors.is_empty() {
        return Err(LpmError::Script(format!(
            "removed patch entries from package.json, but failed to delete patch file(s): {}",
            delete_errors.join(", ")
        )));
    }

    Ok(plan.outcome)
}

fn resolve_patch_remove_selector(
    selector: &str,
    patches: &serde_json::Map<String, serde_json::Value>,
    name_to_keys: &BTreeMap<String, Vec<String>>,
) -> Result<String, LpmError> {
    match parse_patch_selector(selector)? {
        PatchSelector::Exact { name, version } => {
            let key = format!("{name}@{version}");
            if patches.contains_key(&key) {
                Ok(key)
            } else {
                Err(LpmError::Script(format!(
                    "no patch entry found for {key}; run `lpm patch-remove` with an existing `lpm.patchedDependencies` key"
                )))
            }
        }
        PatchSelector::BareName(name) => {
            let matches = name_to_keys
                .get(&name)
                .map(Vec::as_slice)
                .unwrap_or_default();
            match matches.len() {
                0 => Err(LpmError::Script(format!("no patch entry found for {name}"))),
                1 => Ok(matches[0].clone()),
                _ => Err(LpmError::Script(format!(
                    "patch selector {name:?} is ambiguous; specify a precise version: {}",
                    matches.join(", ")
                ))),
            }
        }
        PatchSelector::Range { name, range } => Err(LpmError::Script(format!(
            "patch-remove does not accept range selector {name}@{range}; use an exact patched key or a unique bare package name"
        ))),
    }
}

fn is_patch_artifact_path(relative: &Path) -> bool {
    let mut components = relative.components();
    matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(root)), Some(_)) if root == "patches"
    )
}

fn remove_patch_entries_from_value(
    value: &mut serde_json::Value,
    removed_keys: &BTreeSet<String>,
) -> Result<(), LpmError> {
    let root = value
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json root is not an object".into()))?;
    let Some(lpm) = root.get_mut("lpm") else {
        return Ok(());
    };
    let lpm_obj = lpm
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json `lpm` is not an object".into()))?;
    let Some(patches) = lpm_obj.get_mut("patchedDependencies") else {
        return Ok(());
    };
    let patches_obj = patches.as_object_mut().ok_or_else(|| {
        LpmError::Script("package.json `lpm.patchedDependencies` is not an object".into())
    })?;
    for key in removed_keys {
        patches_obj.remove(key);
    }
    if patches_obj.is_empty() {
        lpm_obj.remove("patchedDependencies");
    }
    if lpm_obj.is_empty() {
        root.remove("lpm");
    }
    Ok(())
}

struct PatchCommitManifestPlan {
    manifest: serde_json::Value,
    manifest_bytes: Vec<u8>,
    obsolete_patch: Option<PathBuf>,
}

fn plan_package_json_patch_update(
    project_dir: &Path,
    key: &str,
    patch_file_rel: &str,
    integrity: &str,
) -> Result<PatchCommitManifestPlan, LpmError> {
    let pkg_path = project_dir.join("package.json");
    let project_root = crate::patch_fs::SafeRoot::open(project_dir)?;
    let manifest_bytes = project_root
        .read_regular_file(
            Path::new("package.json"),
            lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        )
        .map_err(|error| {
            LpmError::Script(format!("package.json at {pkg_path:?} unreadable: {error}"))
        })?;
    let raw = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| LpmError::Script("package.json is not valid UTF-8".into()))?;
    let mut manifest: serde_json::Value = serde_json::from_str(lpm_common::strip_utf8_bom_str(raw))
        .map_err(|error| LpmError::Script(format!("package.json malformed: {error}")))?;
    let new_path = crate::patch_fs::validate_manifest_patch_path(patch_file_rel)?;

    let lpm = manifest
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json root is not an object".into()))?
        .entry("lpm".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let lpm_obj = lpm
        .as_object_mut()
        .ok_or_else(|| LpmError::Script("package.json `lpm` is not an object".into()))?;
    let patches = lpm_obj
        .entry("patchedDependencies".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let patches_obj = patches.as_object_mut().ok_or_else(|| {
        LpmError::Script("package.json `lpm.patchedDependencies` is not an object".into())
    })?;

    let prior_path = patches_obj
        .get(key)
        .and_then(|entry| entry.get("path"))
        .and_then(serde_json::Value::as_str)
        .map(crate::patch_fs::validate_manifest_patch_path)
        .transpose()?;
    let prior_path_is_shared = prior_path.as_ref().is_some_and(|prior| {
        patches_obj.iter().any(|(other_key, entry)| {
            other_key != key
                && entry
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|raw| crate::patch_fs::validate_manifest_patch_path(raw).ok())
                    .is_some_and(|other| other == *prior)
        })
    });
    let obsolete_patch = match prior_path {
        Some(prior)
            if prior != new_path
                && !prior_path_is_shared
                && is_patch_artifact_path(&prior)
                && project_root.regular_file_exists(&prior)? =>
        {
            Some(prior)
        }
        _ => None,
    };

    patches_obj.insert(
        key.to_string(),
        json!({
            "path": patch_file_rel,
            "originalIntegrity": integrity,
        }),
    );

    Ok(PatchCommitManifestPlan {
        manifest,
        manifest_bytes,
        obsolete_patch,
    })
}

/// Inject `lpm.patchedDependencies.<key>` into `package.json` using the
/// JSON Value mutation pattern. Same approach as `add.rs` — `serde_json`
/// has `preserve_order` enabled at the workspace level, so existing key
/// order is preserved.
#[cfg(test)]
fn update_package_json_patches(
    project_dir: &Path,
    key: &str,
    patch_file_rel: &str,
    integrity: &str,
) -> Result<(), LpmError> {
    let plan = plan_package_json_patch_update(project_dir, key, patch_file_rel, integrity)?;
    write_package_json_value(project_dir, &plan.manifest)
}

fn upsert_lockfile_patch_record(
    project_dir: &Path,
    key: &str,
    patch_file_rel: &str,
    patch_sha256: &str,
    integrity: &str,
) -> Result<bool, LpmError> {
    let mut lockfile = match crate::commands::install::workspace_lockfile::read_project(project_dir)
    {
        Ok(lockfile) => lockfile,
        Err(lpm_lockfile::LockfileError::NotFound(_)) => return Ok(false),
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read lpm.lock while recording patch checksum: {error}"
            )));
        }
    };
    lockfile.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION;
    lockfile.patches.insert(
        key.to_string(),
        LockfilePatch {
            path: patch_file_rel.to_string(),
            sha256: patch_sha256.to_string(),
            original_integrity: integrity.to_string(),
        },
    );
    let lockfile_path = crate::commands::install::workspace_lockfile::write(project_dir, lockfile)
        .map_err(|e| {
            LpmError::Script(format!(
                "failed to write lpm.lock after recording patch checksum: {e}"
            ))
        })?;
    lpm_lockfile::ensure_gitattributes(lockfile_path.parent().unwrap_or(project_dir)).map_err(
        |e| {
            LpmError::Script(format!(
                "failed to ensure .gitattributes after recording patch checksum: {e}"
            ))
        },
    )?;
    Ok(true)
}

fn remove_lockfile_patch_records(
    project_dir: &Path,
    removed_keys: &BTreeSet<String>,
) -> Result<bool, LpmError> {
    if removed_keys.is_empty() {
        return Ok(false);
    }

    let mut lockfile = match crate::commands::install::workspace_lockfile::read_project(project_dir)
    {
        Ok(lockfile) => lockfile,
        Err(lpm_lockfile::LockfileError::NotFound(_)) => return Ok(false),
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read lpm.lock while removing patch records: {error}"
            )));
        }
    };
    let before = lockfile.patches.len();
    for key in removed_keys {
        lockfile.patches.remove(key);
    }
    if lockfile.patches.len() == before {
        return Ok(false);
    }

    lockfile.metadata.lockfile_version = lpm_lockfile::LOCKFILE_VERSION;
    let lockfile_path = crate::commands::install::workspace_lockfile::write(project_dir, lockfile)
        .map_err(|e| {
            LpmError::Script(format!(
                "failed to write lpm.lock after removing patch records: {e}"
            ))
        })?;
    lpm_lockfile::ensure_gitattributes(lockfile_path.parent().unwrap_or(project_dir)).map_err(
        |e| {
            LpmError::Script(format!(
                "failed to ensure .gitattributes after removing patch checksum records: {e}"
            ))
        },
    )?;
    Ok(true)
}

fn write_package_json_value(project_dir: &Path, value: &serde_json::Value) -> Result<(), LpmError> {
    let mut output = serde_json::to_string_pretty(value)
        .map_err(|e| LpmError::Script(format!("failed to re-serialize package.json: {e}")))?;
    if !output.ends_with('\n') {
        output.push('\n');
    }

    crate::patch_fs::SafeRoot::open(project_dir)?.write_regular_file(
        Path::new("package.json"),
        output.as_bytes(),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn write_pkg(dir: &Path, content: &str) -> PathBuf {
        let p = dir.join("package.json");
        std::fs::write(&p, content).unwrap();
        p
    }

    fn read_pkg(dir: &Path) -> serde_json::Value {
        let raw = std::fs::read_to_string(dir.join("package.json")).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn update_package_json_creates_lpm_section_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "myproject",
  "version": "1.0.0"
}"#,
        );

        update_package_json_patches(
            dir.path(),
            "lodash@4.17.21",
            "patches/lodash@4.17.21.patch",
            "sha512-aaa",
        )
        .unwrap();

        let v = read_pkg(dir.path());
        assert_eq!(
            v["lpm"]["patchedDependencies"]["lodash@4.17.21"]["path"],
            "patches/lodash@4.17.21.patch"
        );
        assert_eq!(
            v["lpm"]["patchedDependencies"]["lodash@4.17.21"]["originalIntegrity"],
            "sha512-aaa"
        );
        // Existing fields preserved
        assert_eq!(v["name"], "myproject");
        assert_eq!(v["version"], "1.0.0");
    }

    #[test]
    fn update_package_json_extends_existing_lpm_section() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "myproject",
  "lpm": {
    "trustedDependencies": ["esbuild"]
  }
}"#,
        );

        update_package_json_patches(
            dir.path(),
            "foo@1.0.0",
            "patches/foo@1.0.0.patch",
            "sha512-foo",
        )
        .unwrap();

        let v = read_pkg(dir.path());
        // Existing trustedDependencies preserved
        assert_eq!(v["lpm"]["trustedDependencies"][0], "esbuild");
        // New patch entry present
        assert_eq!(
            v["lpm"]["patchedDependencies"]["foo@1.0.0"]["path"],
            "patches/foo@1.0.0.patch"
        );
    }

    #[test]
    fn update_package_json_replaces_existing_patch_entry() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "x",
  "lpm": {
    "patchedDependencies": {
      "lodash@4.17.21": {
        "path": "patches/old.patch",
        "originalIntegrity": "sha512-old"
      }
    }
  }
}"#,
        );

        update_package_json_patches(
            dir.path(),
            "lodash@4.17.21",
            "patches/lodash@4.17.21.patch",
            "sha512-new",
        )
        .unwrap();

        let v = read_pkg(dir.path());
        assert_eq!(
            v["lpm"]["patchedDependencies"]["lodash@4.17.21"]["path"],
            "patches/lodash@4.17.21.patch"
        );
        assert_eq!(
            v["lpm"]["patchedDependencies"]["lodash@4.17.21"]["originalIntegrity"],
            "sha512-new"
        );
    }

    #[test]
    fn patch_update_retains_prior_artifact_referenced_by_another_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("patches")).unwrap();
        std::fs::write(dir.path().join("patches/shared.patch"), "diff").unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "x",
  "lpm": {
    "patchedDependencies": {
      "a@1.0.0": { "path": "patches/shared.patch", "originalIntegrity": "sha512-a" },
      "b@1.0.0": { "path": "patches/shared.patch", "originalIntegrity": "sha512-b" }
    }
  }
}"#,
        );

        let plan = plan_package_json_patch_update(
            dir.path(),
            "a@1.0.0",
            "patches/a@1.0.0.patch",
            "sha512-new",
        )
        .unwrap();

        assert!(plan.obsolete_patch.is_none());
        assert!(dir.path().join("patches/shared.patch").exists());
    }

    #[test]
    fn update_package_json_preserves_top_level_key_order() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "x",
  "version": "1.0.0",
  "scripts": { "build": "tsc" },
  "dependencies": { "lodash": "^4.17.21" }
}"#,
        );

        update_package_json_patches(
            dir.path(),
            "lodash@4.17.21",
            "patches/lodash@4.17.21.patch",
            "sha512-aa",
        )
        .unwrap();

        // Read raw bytes — the preserve_order feature on serde_json
        // means the original key order is retained.
        let raw = std::fs::read_to_string(dir.path().join("package.json")).unwrap();
        let pos_name = raw.find("\"name\"").unwrap();
        let pos_version = raw.find("\"version\"").unwrap();
        let pos_scripts = raw.find("\"scripts\"").unwrap();
        let pos_deps = raw.find("\"dependencies\"").unwrap();
        assert!(pos_name < pos_version);
        assert!(pos_version < pos_scripts);
        assert!(pos_scripts < pos_deps);
    }

    #[test]
    fn update_package_json_fails_on_malformed_input() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(dir.path(), "{ this is not json");
        let err = update_package_json_patches(
            dir.path(),
            "lodash@4.17.21",
            "patches/lodash@4.17.21.patch",
            "sha512-aa",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("malformed"));
    }

    #[test]
    fn patch_remove_exact_key_removes_manifest_entry_and_deletes_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("patches")).unwrap();
        std::fs::write(dir.path().join("patches/lodash@4.17.21.patch"), "diff").unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "x",
  "lpm": {
    "patchedDependencies": {
      "lodash@4.17.21": {
        "path": "patches/lodash@4.17.21.patch",
        "originalIntegrity": "sha512-old"
      }
    }
  }
}"#,
        );

        let outcome =
            remove_package_json_patches(dir.path(), &["lodash@4.17.21".to_string()], false, false)
                .unwrap();

        assert_eq!(outcome.removed[0].key, "lodash@4.17.21");
        assert!(outcome.removed[0].deleted_patch_file);
        assert!(!dir.path().join("patches/lodash@4.17.21.patch").exists());
        let v = read_pkg(dir.path());
        assert!(v.get("lpm").is_none());
    }

    #[test]
    fn patch_remove_bare_name_requires_unique_match() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "lpm": {
    "patchedDependencies": {
      "lodash@3.10.1": { "path": "patches/lodash@3.10.1.patch", "originalIntegrity": "sha512-a" },
      "lodash@4.17.21": { "path": "patches/lodash@4.17.21.patch", "originalIntegrity": "sha512-b" }
    }
  }
}"#,
        );

        let err = remove_package_json_patches(dir.path(), &["lodash".to_string()], false, true)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("ambiguous"));
        assert!(msg.contains("lodash@3.10.1"));
        assert!(msg.contains("lodash@4.17.21"));
    }

    #[test]
    fn patch_remove_keeps_file_when_still_referenced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("patches")).unwrap();
        std::fs::write(dir.path().join("patches/shared.patch"), "diff").unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "lpm": {
    "patchedDependencies": {
      "a@1.0.0": { "path": "patches/shared.patch", "originalIntegrity": "sha512-a" },
      "b@1.0.0": { "path": "patches/shared.patch", "originalIntegrity": "sha512-b" }
    }
  }
}"#,
        );

        let outcome =
            remove_package_json_patches(dir.path(), &["a@1.0.0".to_string()], false, false)
                .unwrap();

        assert!(!outcome.removed[0].deleted_patch_file);
        assert_eq!(
            outcome.removed[0].retained_reason.as_deref(),
            Some("still referenced by another patch")
        );
        assert!(dir.path().join("patches/shared.patch").exists());
        let v = read_pkg(dir.path());
        assert!(v["lpm"]["patchedDependencies"].get("a@1.0.0").is_none());
        assert!(v["lpm"]["patchedDependencies"].get("b@1.0.0").is_some());
    }

    #[test]
    fn patch_remove_dry_run_does_not_mutate_manifest_or_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("patches")).unwrap();
        std::fs::write(dir.path().join("patches/a.patch"), "diff").unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "lpm": {
    "patchedDependencies": {
      "a@1.0.0": { "path": "patches/a.patch", "originalIntegrity": "sha512-a" }
    }
  }
}"#,
        );
        let before = std::fs::read_to_string(dir.path().join("package.json")).unwrap();

        let outcome =
            remove_package_json_patches(dir.path(), &["a@1.0.0".to_string()], true, false).unwrap();

        assert!(!outcome.removed[0].deleted_patch_file);
        assert_eq!(
            before,
            std::fs::read_to_string(dir.path().join("package.json")).unwrap()
        );
        assert!(dir.path().join("patches/a.patch").exists());
    }

    #[test]
    fn patch_remove_refuses_to_delete_parent_escape_path() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "lpm": {
    "patchedDependencies": {
      "a@1.0.0": { "path": "../outside.patch", "originalIntegrity": "sha512-a" }
    }
  }
}"#,
        );

        let err = remove_package_json_patches(dir.path(), &["a@1.0.0".to_string()], false, false)
            .unwrap_err();
        assert!(format!("{err}").contains("unsafe patch path"));
        let v = read_pkg(dir.path());
        assert!(v["lpm"]["patchedDependencies"].get("a@1.0.0").is_some());
    }

    #[test]
    fn patch_remove_aborts_when_manifest_changes_after_planning() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("patches")).unwrap();
        std::fs::write(dir.path().join("patches/a.patch"), "diff").unwrap();
        write_pkg(
            dir.path(),
            r#"{
  "name": "x",
  "lpm": {
    "patchedDependencies": {
      "a@1.0.0": { "path": "patches/a.patch", "originalIntegrity": "sha512-a" }
    }
  }
}"#,
        );
        let plan =
            plan_package_json_patch_removal(dir.path(), &["a@1.0.0".to_string()], false, false)
                .unwrap();
        let changed = r#"{
  "name": "x",
  "description": "concurrent edit",
  "lpm": {
    "patchedDependencies": {
      "a@1.0.0": { "path": "patches/a.patch", "originalIntegrity": "sha512-a" }
    }
  }
}"#;
        write_pkg(dir.path(), changed);

        assert!(apply_package_json_patch_removal(dir.path(), plan).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
            changed
        );
        assert!(dir.path().join("patches/a.patch").exists());
    }

    /// **Slice A structural contract.** `read_lockfile_for_patch_selector`
    /// is the pre-lock branch point for bare-name / range selectors:
    /// it MUST error out before `run_patch` reaches
    /// `with_shared_lock_async`. The test verifies that a project
    /// without an `lpm.lock` produces an actionable error here — which,
    /// because of Rust's `?` control flow, propagates back through
    /// `run_patch` BEFORE the store lock is even acquired.
    ///
    /// This is the structural proof for the "no global store lock held
    /// during selector failure" guarantee. We do NOT spin up a second
    /// process to time-race a second `lpm patch` (flaky on slow CI
    /// runners); the lock-scope contract is enforced by the code's
    /// branch order, which this test exercises directly.
    #[test]
    fn read_lockfile_for_patch_selector_errors_with_actionable_hint_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_lockfile_for_patch_selector(dir.path()).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("lockfile"), "got: {msg}");
        assert!(msg.contains("lpm install"), "got: {msg}");
        assert!(msg.contains("exact pin"), "got: {msg}");
    }

    /// Companion to the above: a well-formed `lpm.lock` is read cleanly.
    #[test]
    fn read_lockfile_for_patch_selector_loads_valid_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.lock"),
            "[metadata]\nlockfile-version = 2\nresolved-with = \"test\"\n\n\
             [[packages]]\nname = \"lodash\"\nversion = \"4.17.21\"\n\
             source = \"registry+https://registry.npmjs.org\"\n",
        )
        .unwrap();
        let lf = read_lockfile_for_patch_selector(dir.path()).unwrap();
        assert_eq!(lf.packages.len(), 1);
        assert_eq!(lf.packages[0].name, "lodash");
        assert_eq!(lf.packages[0].version, "4.17.21");
    }
}
