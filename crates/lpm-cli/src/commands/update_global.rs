//! `lpm global update [pkg|pkg@spec]` — phase 37 M3.4.
//!
//! Three-phase upgrade tx, structurally similar to M3.2's install
//! pipeline but with three differences:
//!
//! 1. **Existing-row required.** prepare errors if `[packages.<pkg>]`
//!    is absent — upgrade is for installs that already exist.
//! 2. **Snapshot prior state in the WAL Intent.**
//!    `prior_active_row_json` + `prior_command_ownership_json` carry
//!    the data recovery's `roll_back` needs to restore on failure
//!    (re-emit shims pointing at the old install root, restore prior
//!    alias rows).
//! 3. **Atomic shim swap at commit.** Same command names, new install
//!    root — `emit_shim` does the rename-over-existing dance. Old
//!    install root goes onto `manifest.tombstones` for `store gc`.
//!
//! `lpm global update` (no arg) iterates every package and re-resolves
//! against its persisted `saved_spec`. `lpm global update <pkg>` does
//! the same scoped to one package. `lpm global update <pkg>@<spec>`
//! rewrites the saved_spec via Phase 33's `decide_saved_dependency_spec`
//! before resolving.
//!
//! `--dry-run` runs every step up to `prepare_locked` but releases
//! the lock without writing anything; the upgrade plan is printed.

use crate::output;
use crate::save_spec::{
    SaveConfig, SaveFlags, UserSaveIntent, decide_saved_dependency_spec, parse_user_save_intent,
};
use chrono::Utc;
use lpm_common::{LpmError, LpmRoot, with_exclusive_lock};
use lpm_global::{
    CommandCollision, InstallReadyMarker, InstallRootStatus, IntentPayload, PackageEntry,
    PackageSource, PendingEntry, Shim, TxKind, WalRecord, WalWriter, emit_shim,
    find_command_collisions, read_for, validate_install_root, write_for, write_marker,
};
use lpm_registry::RegistryClient;
use lpm_semver::{Version, VersionReq};
use owo_colors::OwoColorize;
use std::path::PathBuf;

pub async fn run(package: Option<&str>, dry_run: bool, json_output: bool) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    let registry = build_registry();

    let targets = match package {
        Some(spec) => vec![parse_target(spec)?],
        None => collect_all_targets(&root)?,
    };

    if targets.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "updated": [],
                    "skipped": [],
                    "dry_run": dry_run,
                }))
                .unwrap()
            );
        } else {
            output::info("No globally-installed packages to update.");
        }
        return Ok(());
    }

    let mut plans: Vec<UpgradePlan> = Vec::new();
    for target in &targets {
        match plan_upgrade(&root, &registry, target).await {
            Ok(plan) => plans.push(plan),
            Err(e) => {
                if !json_output {
                    output::warn(&format!("planning {}: {e}", target.name.bold()));
                }
                // Continue planning other targets — one bad spec doesn't
                // block the bulk update.
                plans.push(UpgradePlan::PlanError {
                    package: target.name.clone(),
                    reason: e.to_string(),
                });
            }
        }
    }

    if dry_run {
        emit_dry_run(&plans, json_output);
        return Ok(());
    }

    let mut results: Vec<UpgradeResult> = Vec::new();
    for plan in plans {
        match plan {
            UpgradePlan::Upgrade(prep) => match execute_upgrade(&root, &registry, prep, json_output).await {
                Ok(out) => results.push(UpgradeResult::Upgraded(out)),
                Err(e) => results.push(UpgradeResult::Failed {
                    package: e.0,
                    reason: e.1.to_string(),
                }),
            },
            UpgradePlan::SaveSpecRewrite {
                package,
                version,
                old_saved_spec,
                new_saved_spec,
                prior_snapshot,
            } => {
                match execute_saved_spec_rewrite(
                    &root,
                    &package,
                    &old_saved_spec,
                    &new_saved_spec,
                    &prior_snapshot,
                ) {
                    Ok(()) => results.push(UpgradeResult::SaveSpecRewritten {
                        package,
                        version,
                        old_saved_spec,
                        new_saved_spec,
                    }),
                    Err(e) => results.push(UpgradeResult::Failed {
                        package,
                        reason: e.to_string(),
                    }),
                }
            }
            UpgradePlan::AlreadyCurrent { package, version } => {
                results.push(UpgradeResult::AlreadyCurrent { package, version });
            }
            UpgradePlan::PlanError { package, reason } => {
                results.push(UpgradeResult::Failed { package, reason });
            }
        }
    }

    // Opportunistic tombstone sweep (Phase 37 M3.5). Each successful
    // upgrade pushed the prior install root onto `manifest.tombstones`;
    // run one non-blocking sweep after the bulk loop (rather than one
    // per package) so a 50-package bulk update doesn't serialise 50
    // lock acquires. Bulk updates are the common case where this
    // matters. Best-effort — never fails the caller.
    crate::commands::global::run_opportunistic_sweep(&root);

    emit_results(&results, json_output);

    // Audit Medium (M3.4 round): exit non-zero on any failure so shell
    // automation can detect partial / total bulk-update failures.
    // Single-target update failure also surfaces here. A future
    // `--continue-on-error` flag could opt out for users who want
    // best-effort-bulk semantics.
    //
    // Audit pass-2 Medium 2: in --json mode, `emit_results` has already
    // written a structured `{"success": false, "failed": [...]}` document
    // to stdout. Returning `LpmError::Script(...)` here would make the
    // top-level handler in `main.rs` emit a *second* JSON document,
    // breaking the single-JSON-document contract. Route through
    // `LpmError::ExitCode(1)` so main.rs skips the top-level emit path
    // while still propagating a non-zero exit status.
    let failed: Vec<&str> = results
        .iter()
        .filter_map(|r| match r {
            UpgradeResult::Failed { package, .. } => Some(package.as_str()),
            _ => None,
        })
        .collect();
    if !failed.is_empty() {
        if json_output {
            return Err(LpmError::ExitCode(1));
        }
        return Err(LpmError::Script(format!(
            "{} package(s) failed to update: {}",
            failed.len(),
            failed.join(", ")
        )));
    }
    Ok(())
}

// ─── Target parsing ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Target {
    /// Package name as keyed in `[packages.*]`.
    name: String,
    /// `Some(intent)` when the user typed `pkg@spec` — Phase 33 decides
    /// the new saved_spec from this. `None` means "re-resolve against
    /// the existing saved_spec," which is the bulk-update default and
    /// the `lpm global update <pkg>` (no version) shape.
    new_intent: Option<UserSaveIntent>,
}

fn parse_target(spec: &str) -> Result<Target, LpmError> {
    let (name, intent) = parse_user_save_intent(spec);
    let new_intent = if matches!(&intent, UserSaveIntent::Bare) {
        None
    } else {
        Some(intent)
    };
    Ok(Target { name, new_intent })
}

fn collect_all_targets(root: &LpmRoot) -> Result<Vec<Target>, LpmError> {
    let manifest = read_for(root)?;
    Ok(manifest
        .packages
        .keys()
        .map(|name| Target {
            name: name.clone(),
            new_intent: None,
        })
        .collect())
}

// ─── Planning ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum UpgradePlan {
    /// Resolved version differs from the active one — full upgrade tx.
    Upgrade(Box<UpgradePrep>),
    /// Resolved version is unchanged but the user typed a `<pkg>@<spec>`
    /// that produces a different `saved_spec` — manifest-only mutation
    /// that retunes the bulk-update tracking policy without touching
    /// the install root. Audit Medium from the M3.4 round: previously
    /// `update pkg@^3` on an exact-pinned 3.8.3 install was reported
    /// as "already current," locking the user out of relaxing the pin
    /// without a version bump.
    ///
    /// `prior_snapshot` carries the full pre-rewrite row (same shape
    /// as Upgrade's `prior_active_row_json`). The execute step
    /// re-validates the WHOLE row under the lock — not just
    /// `saved_spec` — so a concurrent upgrade that landed between
    /// planning and rewrite can't "retune" the new active row with a
    /// stale plan (audit Medium from M3.4 audit pass-2). Example the
    /// audit caught: plan rewrite ^3 → 3.8.3 on 3.8.3, concurrent
    /// upgrade to 3.8.4 (still ^3), pre-fix the rewrite would have
    /// pinned the now-3.8.4 install to "3.8.3."
    SaveSpecRewrite {
        package: String,
        version: String,
        old_saved_spec: String,
        new_saved_spec: String,
        prior_snapshot: Box<serde_json::Value>,
    },
    /// No version change AND no saved_spec change.
    AlreadyCurrent {
        package: String,
        version: String,
    },
    PlanError {
        package: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
struct UpgradePrep {
    name: String,
    current_version: String,
    new_version: Version,
    new_saved_spec: String,
    new_integrity: String,
    source: PackageSource,
    /// Snapshot of the existing `[packages.<name>]` row, taken at
    /// planning time. Lands in the WAL Intent's `prior_active_row_json`
    /// so recovery's `roll_back` can restore it on failure.
    prior_active_row_json: serde_json::Value,
    /// Snapshot of `[aliases]` rows owned by this package. Recovery
    /// uses `prior_command_ownership_json.aliases` to restore the
    /// pre-upgrade alias state.
    prior_aliases_json: serde_json::Value,
}

async fn plan_upgrade(
    root: &LpmRoot,
    registry: &RegistryClient,
    target: &Target,
) -> Result<UpgradePlan, LpmError> {
    let manifest = read_for(root)?;
    let active = manifest.packages.get(&target.name).ok_or_else(|| {
        LpmError::Script(format!(
            "'{}' is not globally installed. Run `lpm install -g {}` first.",
            target.name, target.name
        ))
    })?;

    // `decide_saved_dependency_spec` needs a UserSaveIntent. For bulk
    // update / `lpm global update <pkg>`, we re-resolve against the
    // existing saved_spec — i.e. treat the persisted spec as a Range
    // and look for the highest matching newer version. For the
    // `pkg@spec` form, the user-typed intent overrides.
    let intent = match &target.new_intent {
        Some(i) => i.clone(),
        None => infer_intent_from_saved_spec(&active.saved_spec),
    };

    // Dispatch by name shape — same as install_global.
    let metadata = if lpm_common::package_name::is_lpm_package(&target.name) {
        let pkg_name = lpm_common::PackageName::parse(&target.name).map_err(|e| {
            LpmError::Script(format!("invalid LPM package name '{}': {e}", target.name))
        })?;
        registry.get_package_metadata(&pkg_name).await?
    } else {
        registry.get_npm_package_metadata(&target.name).await?
    };

    let new_version_str = pick_version(&metadata, &intent)?;
    let new_version = Version::parse(&new_version_str).map_err(|e| {
        LpmError::Script(format!(
            "registry returned unparseable version '{new_version_str}' for '{}': {e}",
            target.name
        ))
    })?;

    // Compute the new saved_spec via Phase 33 BEFORE the
    // already-current check. Pre-fix this was computed only for the
    // upgrade branch, so a `pkg@^3` rewrite on an exact-pinned 3.8.3
    // install fell into AlreadyCurrent and the saved_spec stayed
    // "3.8.3" — locking the user out of relaxing the pin without a
    // version bump (audit Medium from M3.4 round). We need this value
    // either way: full upgrade uses it for the pending row, save-spec
    // rewrite uses it as the manifest-only mutation target.
    let new_saved_spec = decide_saved_dependency_spec(
        &intent,
        &new_version,
        SaveFlags::default(),
        SaveConfig::default(),
    )?
    .spec_to_write;

    // Snapshot the active row up-front. Both the Upgrade and
    // SaveSpecRewrite branches need it for the under-lock match
    // check that prevents stale-plan lost updates.
    let prior_active_row_json = serde_json::json!({
        "saved_spec": active.saved_spec,
        "resolved": active.resolved,
        "integrity": active.integrity,
        "source": serde_json::to_value(active.source).unwrap(),
        "installed_at": active.installed_at.to_rfc3339(),
        "root": active.root,
        "commands": active.commands,
    });

    // Three-way classification:
    //   resolved differs            → Upgrade
    //   resolved same, saved_spec differs → SaveSpecRewrite
    //   both unchanged              → AlreadyCurrent
    if new_version.to_string() == active.resolved {
        if new_saved_spec != active.saved_spec {
            return Ok(UpgradePlan::SaveSpecRewrite {
                package: target.name.clone(),
                version: active.resolved.clone(),
                old_saved_spec: active.saved_spec.clone(),
                new_saved_spec,
                prior_snapshot: Box::new(prior_active_row_json),
            });
        }
        return Ok(UpgradePlan::AlreadyCurrent {
            package: target.name.clone(),
            version: active.resolved.clone(),
        });
    }

    let version_meta = metadata.versions.get(&new_version_str).ok_or_else(|| {
        LpmError::Script(format!(
            "version '{new_version_str}' missing from metadata for '{}'",
            target.name
        ))
    })?;
    let new_integrity = version_meta
        .dist
        .as_ref()
        .and_then(|d| d.integrity.clone())
        .ok_or_else(|| {
            LpmError::Script(format!(
                "version '{new_version_str}' of '{}' has no integrity hash in registry metadata",
                target.name
            ))
        })?;

    let source = if lpm_common::package_name::is_lpm_package(&target.name) {
        PackageSource::LpmDev
    } else {
        PackageSource::UpstreamNpm
    };

    let alias_map: serde_json::Map<String, serde_json::Value> = manifest
        .aliases
        .iter()
        .filter(|(_, e)| e.package == target.name)
        .map(|(name, e)| {
            (
                name.clone(),
                serde_json::json!({"package": e.package, "bin": e.bin}),
            )
        })
        .collect();

    Ok(UpgradePlan::Upgrade(Box::new(UpgradePrep {
        name: target.name.clone(),
        current_version: active.resolved.clone(),
        new_version,
        new_saved_spec,
        new_integrity,
        source,
        prior_active_row_json,
        prior_aliases_json: serde_json::Value::Object(alias_map),
    })))
}

/// Infer a UserSaveIntent from a persisted saved_spec string. The
/// saved_spec was already produced by `decide_saved_dependency_spec`
/// at install time, so it's always a valid range / exact / wildcard
/// spec. For bulk-update we treat it as a Range so the next call to
/// `decide_saved_dependency_spec` preserves the user's original
/// shape (caret stays caret, tilde stays tilde, exact stays exact).
fn infer_intent_from_saved_spec(saved_spec: &str) -> UserSaveIntent {
    if saved_spec == "*" {
        return UserSaveIntent::Wildcard;
    }
    if saved_spec.starts_with("workspace:") {
        return UserSaveIntent::Workspace(saved_spec.to_string());
    }
    if Version::parse(saved_spec).is_ok() {
        return UserSaveIntent::Exact(saved_spec.to_string());
    }
    UserSaveIntent::Range(saved_spec.to_string())
}

fn pick_version(
    metadata: &lpm_registry::PackageMetadata,
    intent: &UserSaveIntent,
) -> Result<String, LpmError> {
    // Same as install_global::pick_version. Duplicated rather than
    // shared to keep the install/update modules independent during
    // M3.4 development; we can extract a shared helper later.
    let token = match intent {
        UserSaveIntent::Bare => "latest".to_string(),
        UserSaveIntent::Exact(s) => return Ok(s.clone()),
        UserSaveIntent::Range(s) => s.clone(),
        UserSaveIntent::DistTag(t) => t.clone(),
        UserSaveIntent::Wildcard => "*".to_string(),
        UserSaveIntent::Workspace(_) => {
            return Err(LpmError::Script(
                "global update does not support workspace: protocol".into(),
            ));
        }
    };
    if let Some(v) = metadata.dist_tags.get(&token) {
        return Ok(v.clone());
    }
    let req = VersionReq::parse(&token)
        .map_err(|e| LpmError::Script(format!("could not parse version token '{token}': {e}")))?;
    let mut versions: Vec<Version> = metadata
        .versions
        .keys()
        .filter_map(|s| Version::parse(s).ok())
        .collect();
    if versions.is_empty() {
        return Err(LpmError::Script(format!(
            "registry returned no parseable versions for '{}'",
            metadata.name
        )));
    }
    let refs: Vec<&Version> = versions.iter().collect();
    match lpm_semver::max_satisfying(&refs, &req) {
        Some(v) => Ok(v.to_string()),
        None => {
            versions.sort();
            Err(LpmError::Script(format!(
                "no version of '{}' satisfies '{}'. Available: {}",
                metadata.name,
                token,
                versions
                    .iter()
                    .rev()
                    .take(5)
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    }
}

// ─── Execution ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum UpgradeResult {
    Upgraded(UpgradeOutput),
    /// Manifest-only mutation outcome (no version change). Same shape
    /// as `UpgradePlan::SaveSpecRewrite`. Output emitter renders this
    /// distinctly so users can see "spec retuned, version stayed."
    SaveSpecRewritten {
        package: String,
        version: String,
        old_saved_spec: String,
        new_saved_spec: String,
    },
    AlreadyCurrent {
        package: String,
        version: String,
    },
    Failed {
        package: String,
        reason: String,
    },
}

#[derive(Debug, Clone)]
struct UpgradeOutput {
    name: String,
    from_version: String,
    to_version: String,
    saved_spec: String,
    commands: Vec<String>,
}

async fn execute_upgrade(
    root: &LpmRoot,
    registry: &RegistryClient,
    prep: Box<UpgradePrep>,
    suppress_nested_output: bool,
) -> Result<UpgradeOutput, (String, LpmError)> {
    // Step 1: prepare under .tx.lock
    let staged = with_exclusive_lock(root.global_tx_lock(), || {
        prepare_upgrade_locked(root, &prep)
    })
    .map_err(|e| (prep.name.clone(), e))?;

    // Step 2: slow install (no lock)
    if let Err(e) = do_install_upgrade(registry, &prep, &staged, suppress_nested_output).await {
        return Err((prep.name.clone(), e));
    }
    let commands = match discover_bin_commands(&staged.install_root, &prep.name) {
        Ok(c) => c,
        Err(e) => return Err((prep.name.clone(), e)),
    };
    if commands.is_empty() {
        return Err((
            prep.name.clone(),
            LpmError::Script(format!(
                "package '{}' exposes no bin entries — refusing to upgrade",
                prep.name
            )),
        ));
    }
    let marker = InstallReadyMarker::new(commands);
    if let Err(e) = write_marker(&staged.install_root, &marker) {
        return Err((prep.name.clone(), e));
    }

    // Step 3: validate + commit under .tx.lock
    let output = with_exclusive_lock(root.global_tx_lock(), || {
        commit_upgrade_locked(root, &prep, &staged)
    })
    .map_err(|e| (prep.name.clone(), e))?;

    Ok(output)
}

#[derive(Debug, Clone)]
struct StagedUpgrade {
    tx_id: String,
    install_root: PathBuf,
    install_root_relative: String,
}

fn prepare_upgrade_locked(root: &LpmRoot, prep: &UpgradePrep) -> Result<StagedUpgrade, LpmError> {
    let mut manifest = read_for(root)?;
    // Re-check active state under the lock (prior fetch was outside).
    let active = manifest.packages.get(&prep.name).ok_or_else(|| {
        LpmError::Script(format!(
            "'{}' is no longer installed (someone else uninstalled it). Aborting upgrade.",
            prep.name
        ))
    })?;
    if manifest.pending.contains_key(&prep.name) {
        return Err(LpmError::Script(format!(
            "'{}' has another in-flight transaction. Wait for it to finish.",
            prep.name
        )));
    }
    // **Lost-update guard (audit High from the M3.4 round).** The plan
    // we built outside the lock captured a snapshot of the active row
    // (`prep.prior_active_row_json`). Between then and now another
    // process may have committed its own upgrade of the same package.
    // If we proceed with the stale snapshot, our commit would tombstone
    // *the wrong prior root* and overwrite their active row with our
    // older planned version. Refuse to proceed; tell the user to
    // re-plan against the current state.
    if let Err(diff) = active_matches_planned_snapshot(active, &prep.prior_active_row_json) {
        return Err(LpmError::Script(format!(
            "'{}' was modified by another process between planning and commit ({diff}). \
             Re-run `lpm global update {}` (or whatever spec you used) to plan against the \
             current state.",
            prep.name, prep.name
        )));
    }

    let install_root = root.install_root_for(&prep.name, &prep.new_version.to_string());
    let install_root_relative = format!(
        "installs/{}",
        install_root.file_name().unwrap().to_string_lossy()
    );
    let tx_id = mk_tx_id();

    // Write Intent FIRST, then pending row. Crash between the two →
    // recovery sees Intent without pending → Case C orphan cleanup.
    let mut wal = WalWriter::open(root.global_wal())?;
    let new_row_json = serde_json::json!({
        "saved_spec": prep.new_saved_spec,
        "resolved": prep.new_version.to_string(),
        "integrity": prep.new_integrity,
        "source": serde_json::to_value(prep.source).unwrap(),
        "started_at": Utc::now().to_rfc3339(),
        "root": install_root_relative,
        // commands: discovered post-extract (M3.2 marker-as-authority).
        "commands": Vec::<String>::new(),
        "replaces_version": prep.current_version,
    });
    wal.append(&WalRecord::Intent(Box::new(IntentPayload {
        tx_id: tx_id.clone(),
        kind: TxKind::Upgrade,
        package: prep.name.clone(),
        new_root_path: install_root.clone(),
        new_row_json,
        prior_active_row_json: Some(prep.prior_active_row_json.clone()),
        prior_command_ownership_json: serde_json::json!({
            "aliases": prep.prior_aliases_json,
        }),
        new_aliases_json: serde_json::json!({}),
        // M3.4 upgrade path doesn't resolve collisions (M4.2 scope).
        // Upgrades keep the same package owning the same commands, so
        // `find_command_collisions` never triggers non-self hits.
        ownership_delta: Vec::new(),
    })))?;

    manifest.pending.insert(
        prep.name.clone(),
        PendingEntry {
            saved_spec: prep.new_saved_spec.clone(),
            resolved: prep.new_version.to_string(),
            integrity: prep.new_integrity.clone(),
            source: prep.source,
            started_at: Utc::now(),
            root: install_root_relative.clone(),
            commands: Vec::new(),
            replaces_version: Some(prep.current_version.clone()),
        },
    );
    write_for(root, &manifest)?;

    Ok(StagedUpgrade {
        tx_id,
        install_root,
        install_root_relative,
    })
}

async fn do_install_upgrade(
    registry: &RegistryClient,
    prep: &UpgradePrep,
    staged: &StagedUpgrade,
    suppress_nested_output: bool,
) -> Result<(), LpmError> {
    // Same shape as install_global::do_install. Could share via a
    // helper crate later; duplicated for module independence right
    // now.
    std::fs::create_dir_all(&staged.install_root)?;
    let pkg_json = format!(
        r#"{{"private":true,"name":"@lpm-global-upgrade/{}","dependencies":{{"{}":"{}"}}}}"#,
        sanitize_inner_name(&prep.name),
        prep.name,
        prep.new_version
    );
    std::fs::write(staged.install_root.join("package.json"), &pkg_json)?;

    // In outer --json mode, the aggregate bulk-update result owns
    // stdout. Silence the nested upgrade install so it cannot prepend
    // human install summaries ahead of the final JSON payload.
    let _stdout_gag = crate::output::suppress_stdout(suppress_nested_output)
        .map_err(LpmError::Script)?;

    crate::commands::install::run_with_options(
        registry,
        &staged.install_root,
        false, // json_output
        false, // offline
        false, // force
        false, // allow_new
        None,  // linker_override
        true,  // no_skills
        true,  // no_editor_setup
        true,  // no_security_summary
        false, // auto_build
        None,
        None,
    )
    .await
}

fn sanitize_inner_name(name: &str) -> String {
    name.replace(['@', '/', '.'], "-")
}

fn commit_upgrade_locked(
    root: &LpmRoot,
    prep: &UpgradePrep,
    staged: &StagedUpgrade,
) -> Result<UpgradeOutput, LpmError> {
    let mut manifest = read_for(root)?;

    let status = validate_install_root(&staged.install_root, None)?;
    let marker_commands = match status {
        InstallRootStatus::Ready { commands } => commands,
        other => {
            return Err(LpmError::Script(format!(
                "install root for '{}' failed validation: {other:?}. Recovery will reconcile \
                 on next `lpm` invocation.",
                prep.name
            )));
        }
    };

    // Collision guard. Self-collisions are EXPECTED for upgrades —
    // the new install owns the same command names as the prior one.
    // `find_command_collisions` excludes self-collisions for exactly
    // this case (M3.2 audit pass 2 added that exclusion explicitly
    // for "future M3.4 upgrades"). So a real conflict here means
    // ANOTHER package owns one of the new commands.
    let collisions: Vec<CommandCollision> =
        find_command_collisions(&manifest, &prep.name, &marker_commands);
    if !collisions.is_empty() {
        // Inline rollback: drop pending row, tombstone new install
        // root (recovery sweep will retry the actual delete), write
        // WAL Abort. Manifest stays at the pre-upgrade state.
        rollback_aborted_upgrade(
            root,
            &mut manifest,
            staged,
            &prep.name,
            &format!(
                "command collision with another package: {}",
                collisions
                    .iter()
                    .map(|c| format!("{} (owned by {})", c.command, c.current_owner))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )?;
        return Err(LpmError::Script(format!(
            "upgrade of '{}' would conflict with another globally-installed package's \
             commands: {}. The pre-upgrade install is unchanged. Resolve the conflict (uninstall \
             the other package or wait for M4 alias support) and retry.",
            prep.name,
            collisions
                .iter()
                .map(|c| c.command.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    // Atomic shim swap: emit_shim's tempfile-rename swaps existing
    // shims (same command names, new install root). The user's shell
    // sees either the old or new shim, never neither.
    let bin_dir = root.bin_dir();
    let install_bin = staged.install_root.join("node_modules").join(".bin");
    for cmd in &marker_commands {
        let target = install_bin.join(cmd);
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: cmd.clone(),
                target,
            },
        )?;
    }

    // Flip [pending] → [packages]. Tombstone the OLD install root
    // (its path is in prior_active_row_json.root) so `store gc` can
    // sweep it after any tools holding files in it have exited.
    if let Some(prior_root) = prep
        .prior_active_row_json
        .get("root")
        .and_then(|v| v.as_str())
    {
        manifest.tombstones.push(prior_root.to_string());
    }
    let active = PackageEntry {
        saved_spec: prep.new_saved_spec.clone(),
        resolved: prep.new_version.to_string(),
        integrity: prep.new_integrity.clone(),
        source: prep.source,
        installed_at: Utc::now(),
        root: staged.install_root_relative.clone(),
        commands: marker_commands.clone(),
    };
    manifest.packages.insert(prep.name.clone(), active);
    manifest.pending.remove(&prep.name);

    // Persist BEFORE WAL Commit (M3.1 ordering invariant).
    write_for(root, &manifest)?;

    let mut wal = WalWriter::open(root.global_wal())?;
    wal.append(&WalRecord::Commit {
        tx_id: staged.tx_id.clone(),
        committed_at: Utc::now(),
    })?;

    Ok(UpgradeOutput {
        name: prep.name.clone(),
        from_version: prep.current_version.clone(),
        to_version: prep.new_version.to_string(),
        saved_spec: prep.new_saved_spec.clone(),
        commands: marker_commands,
    })
}

fn rollback_aborted_upgrade(
    root: &LpmRoot,
    manifest: &mut lpm_global::GlobalManifest,
    staged: &StagedUpgrade,
    package: &str,
    reason: &str,
) -> Result<(), LpmError> {
    // Per the M3.1 audit's tombstone pattern: don't try to remove
    // the install root inline (could be locked on Windows by a tool
    // the user is running). Tombstone it for `store gc`.
    if staged.install_root.exists()
        && let Err(e) = std::fs::remove_dir_all(&staged.install_root)
    {
        tracing::debug!("upgrade rollback: deferring install-root cleanup via tombstone: {e}");
        manifest
            .tombstones
            .push(staged.install_root_relative.clone());
    }
    manifest.pending.remove(package);
    write_for(root, manifest)?;
    let mut wal = WalWriter::open(root.global_wal())?;
    wal.append(&WalRecord::Abort {
        tx_id: staged.tx_id.clone(),
        reason: format!("commit-time validation failed: {reason}"),
        aborted_at: Utc::now(),
    })?;
    Ok(())
}

// ─── Output ──────────────────────────────────────────────────────────

fn emit_dry_run(plans: &[UpgradePlan], json_output: bool) {
    if json_output {
        let entries: Vec<_> = plans
            .iter()
            .map(|p| match p {
                UpgradePlan::Upgrade(prep) => serde_json::json!({
                    "package": prep.name,
                    "action": "upgrade",
                    "from": prep.current_version,
                    "to": prep.new_version.to_string(),
                    "saved_spec": prep.new_saved_spec,
                }),
                UpgradePlan::SaveSpecRewrite {
                    package,
                    version,
                    old_saved_spec,
                    new_saved_spec,
                    ..
                } => serde_json::json!({
                    "package": package,
                    "action": "saved_spec_rewrite",
                    "current": version,
                    "from_saved_spec": old_saved_spec,
                    "to_saved_spec": new_saved_spec,
                }),
                UpgradePlan::AlreadyCurrent { package, version } => serde_json::json!({
                    "package": package,
                    "action": "skip",
                    "current": version,
                }),
                UpgradePlan::PlanError { package, reason } => serde_json::json!({
                    "package": package,
                    "action": "plan_error",
                    "reason": reason,
                }),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "dry_run": true,
                "plans": entries,
            }))
            .unwrap()
        );
        return;
    }
    let mut any_action = false;
    for plan in plans {
        match plan {
            UpgradePlan::Upgrade(prep) => {
                any_action = true;
                println!(
                    "  {} {} \u{2192} {}",
                    prep.name.bold(),
                    prep.current_version.dimmed(),
                    prep.new_version.to_string().green()
                );
            }
            UpgradePlan::SaveSpecRewrite {
                package,
                version,
                old_saved_spec,
                new_saved_spec,
                ..
            } => {
                any_action = true;
                println!(
                    "  {} {} (saved_spec {} \u{2192} {})",
                    package.bold(),
                    format!("@{version}").dimmed(),
                    old_saved_spec.dimmed(),
                    new_saved_spec.green()
                );
            }
            UpgradePlan::AlreadyCurrent { package, version } => {
                println!(
                    "  {} {} (already current)",
                    package.dimmed(),
                    format!("@{version}").dimmed()
                );
            }
            UpgradePlan::PlanError { package, reason } => {
                println!(
                    "  {} {} {}",
                    package.bold(),
                    "could not plan:".red(),
                    reason
                );
            }
        }
    }
    if !any_action {
        output::info("Nothing to update.");
    }
}

fn emit_results(results: &[UpgradeResult], json_output: bool) {
    if json_output {
        let entries: Vec<_> = results
            .iter()
            .map(|r| match r {
                UpgradeResult::Upgraded(out) => serde_json::json!({
                    "package": out.name,
                    "action": "upgraded",
                    "from": out.from_version,
                    "to": out.to_version,
                    "saved_spec": out.saved_spec,
                    "commands": out.commands,
                }),
                UpgradeResult::SaveSpecRewritten {
                    package,
                    version,
                    old_saved_spec,
                    new_saved_spec,
                } => serde_json::json!({
                    "package": package,
                    "action": "saved_spec_rewritten",
                    "current": version,
                    "from_saved_spec": old_saved_spec,
                    "to_saved_spec": new_saved_spec,
                }),
                UpgradeResult::AlreadyCurrent { package, version } => serde_json::json!({
                    "package": package,
                    "action": "skip",
                    "current": version,
                }),
                UpgradeResult::Failed { package, reason } => serde_json::json!({
                    "package": package,
                    "action": "failed",
                    "reason": reason,
                }),
            })
            .collect();
        let any_failure = results
            .iter()
            .any(|r| matches!(r, UpgradeResult::Failed { .. }));
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": !any_failure,
                "dry_run": false,
                "results": entries,
            }))
            .unwrap()
        );
        return;
    }
    for r in results {
        match r {
            UpgradeResult::Upgraded(out) => {
                output::success(&format!(
                    "Upgraded {} {} \u{2192} {}",
                    out.name.bold(),
                    out.from_version.dimmed(),
                    out.to_version.green()
                ));
            }
            UpgradeResult::SaveSpecRewritten {
                package,
                version,
                old_saved_spec,
                new_saved_spec,
            } => {
                output::success(&format!(
                    "Retuned {} {} (saved_spec {} \u{2192} {})",
                    package.bold(),
                    format!("@{version}").dimmed(),
                    old_saved_spec.dimmed(),
                    new_saved_spec.green()
                ));
            }
            UpgradeResult::AlreadyCurrent { package, version } => {
                output::info(&format!(
                    "{} {} already current",
                    package.dimmed(),
                    format!("@{version}").dimmed()
                ));
            }
            UpgradeResult::Failed { package, reason } => {
                output::warn(&format!("{}: {reason}", package.bold()));
            }
        }
    }
}

// ─── Helpers (sourced from install_global; small enough to duplicate) ─

/// Manifest-only mutation: change `[packages.<pkg>].saved_spec` to
/// `new_saved_spec`. No install root work, no shim swap. Used when
/// the user's `<pkg>@<spec>` resolves to the same version that's
/// already active but expresses different tracking intent (e.g.
/// going from exact-pinned `3.8.3` to range `^3.8.3` so future bulk
/// updates pick up patches).
///
/// Atomic via the manifest writer's tempfile + rename. Re-validates
/// the WHOLE active row against the planned snapshot under the lock
/// (audit Medium from M3.4 audit pass-2). Pre-fix only saved_spec
/// was compared, which let a concurrent upgrade slide through:
/// plan rewrite ^3 → 3.8.3 on 3.8.3, concurrent upgrade to 3.8.4
/// (still ^3), the rewrite would have pinned the now-3.8.4 install
/// to "3.8.3."
///
/// `old_saved_spec` is kept as a separate parameter only so the
/// "you tried to retune from X to Y but X isn't current" error
/// message names what the user typed; the actual safety check is
/// `active_matches_planned_snapshot`.
fn execute_saved_spec_rewrite(
    root: &LpmRoot,
    package: &str,
    old_saved_spec: &str,
    new_saved_spec: &str,
    prior_snapshot: &serde_json::Value,
) -> Result<(), LpmError> {
    with_exclusive_lock(root.global_tx_lock(), || {
        let mut manifest = read_for(root)?;
        let active = manifest.packages.get(package).ok_or_else(|| {
            LpmError::Script(format!(
                "'{package}' is no longer installed. Aborting saved_spec rewrite."
            ))
        })?;
        if let Err(diff) = active_matches_planned_snapshot(active, prior_snapshot) {
            return Err(LpmError::Script(format!(
                "'{package}' was modified by another process between planning and rewrite \
                 ({diff}). The retune from {old_saved_spec:?} to {new_saved_spec:?} no longer \
                 applies. Re-run `lpm global update {package}@<spec>` to plan against the \
                 current state."
            )));
        }
        // We hold the lock and the snapshot still matches → safe to
        // mutate. Fetch a mutable reference (the immutable borrow
        // above ended at the end of the previous statement).
        let active_mut = manifest
            .packages
            .get_mut(package)
            .expect("just checked it exists");
        active_mut.saved_spec = new_saved_spec.to_string();
        write_for(root, &manifest)
    })
}

/// Compare the current `[packages.<pkg>]` row against the snapshot
/// captured by `plan_upgrade` outside the lock. Returns `Ok(())` when
/// they match on the load-bearing fields (`saved_spec`, `resolved`,
/// `integrity`, `source`, `root`) and `Err(diff_description)` otherwise.
///
/// `installed_at` is intentionally excluded — recovery can rewrite the
/// timestamp, and the timestamp doesn't affect tombstone correctness or
/// `replaces_version` semantics. Same omission as `active_matches_intent`
/// in recover.rs.
fn active_matches_planned_snapshot(
    active: &PackageEntry,
    snapshot: &serde_json::Value,
) -> Result<(), String> {
    let snap = snapshot.as_object().ok_or_else(|| {
        "planned snapshot is not a JSON object (corrupt prior_active_row_json)".to_string()
    })?;
    let str_field = |k: &str| snap.get(k).and_then(|v| v.as_str());

    if str_field("saved_spec") != Some(active.saved_spec.as_str()) {
        return Err(format!(
            "saved_spec changed: planned {:?}, current {:?}",
            str_field("saved_spec"),
            active.saved_spec
        ));
    }
    if str_field("resolved") != Some(active.resolved.as_str()) {
        return Err(format!(
            "resolved version changed: planned {:?}, current {:?}",
            str_field("resolved"),
            active.resolved
        ));
    }
    if str_field("integrity") != Some(active.integrity.as_str()) {
        return Err(format!(
            "integrity changed: planned {:?}, current {:?}",
            str_field("integrity"),
            active.integrity
        ));
    }
    if str_field("root") != Some(active.root.as_str()) {
        return Err(format!(
            "install root changed: planned {:?}, current {:?}",
            str_field("root"),
            active.root
        ));
    }
    let active_source = serde_json::to_value(active.source)
        .ok()
        .and_then(|v| v.as_str().map(String::from));
    if str_field("source") != active_source.as_deref() {
        return Err(format!(
            "source changed: planned {:?}, current {:?}",
            str_field("source"),
            active_source
        ));
    }
    Ok(())
}

fn build_registry() -> RegistryClient {
    let registry_url = std::env::var("LPM_REGISTRY_URL")
        .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string());
    RegistryClient::new().with_base_url(&registry_url)
}

fn mk_tx_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos}-{}", std::process::id())
}

/// Read the installed package's `package.json` to discover bin entries.
/// Same implementation as install_global::discover_bin_commands.
fn discover_bin_commands(
    install_root: &std::path::Path,
    package_name: &str,
) -> Result<Vec<String>, LpmError> {
    let pkg_json_path = install_root
        .join("node_modules")
        .join(package_name)
        .join("package.json");
    let bytes = std::fs::read(&pkg_json_path).map_err(|e| {
        LpmError::Script(format!(
            "could not read installed package.json at {}: {e}",
            pkg_json_path.display()
        ))
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        LpmError::Script(format!(
            "installed package.json is not valid JSON at {}: {e}",
            pkg_json_path.display()
        ))
    })?;
    let Some(bin_field) = value.get("bin") else {
        return Ok(Vec::new());
    };
    let mut commands = Vec::new();
    match bin_field {
        serde_json::Value::String(_) => {
            commands.push(short_name(package_name).to_string());
        }
        serde_json::Value::Object(map) => {
            for k in map.keys() {
                commands.push(k.clone());
            }
        }
        _ => {}
    }
    Ok(commands)
}

fn short_name(package_name: &str) -> &str {
    if let Some(rest) = package_name.strip_prefix('@')
        && let Some(slash) = rest.find('/')
    {
        return &rest[slash + 1..];
    }
    package_name
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scoped_update_env(
        path: &std::path::Path,
        registry_url: Option<&str>,
    ) -> crate::test_env::ScopedEnv {
        let mut vars = vec![("LPM_HOME", Some(path.as_os_str().to_owned()))];
        if let Some(registry_url) = registry_url {
            vars.push(("LPM_REGISTRY_URL", Some(registry_url.into())));
        }
        crate::test_env::ScopedEnv::update(vars)
    }

    #[test]
    fn parse_target_pkg_only_has_no_intent_override() {
        let t = parse_target("eslint").unwrap();
        assert_eq!(t.name, "eslint");
        assert!(t.new_intent.is_none());
    }

    #[test]
    fn parse_target_pkg_at_version_carries_exact_intent() {
        let t = parse_target("eslint@10.0.0").unwrap();
        assert_eq!(t.name, "eslint");
        assert!(matches!(t.new_intent, Some(UserSaveIntent::Exact(v)) if v == "10.0.0"));
    }

    #[test]
    fn parse_target_pkg_at_range_carries_range_intent() {
        let t = parse_target("eslint@^10").unwrap();
        assert_eq!(t.name, "eslint");
        assert!(matches!(t.new_intent, Some(UserSaveIntent::Range(v)) if v == "^10"));
    }

    #[test]
    fn parse_target_pkg_at_dist_tag_carries_disttag_intent() {
        let t = parse_target("eslint@latest").unwrap();
        assert_eq!(t.name, "eslint");
        assert!(matches!(t.new_intent, Some(UserSaveIntent::DistTag(v)) if v == "latest"));
    }

    #[test]
    fn infer_intent_caret_range_stays_range() {
        let intent = infer_intent_from_saved_spec("^9");
        assert!(matches!(intent, UserSaveIntent::Range(v) if v == "^9"));
    }

    #[test]
    fn infer_intent_exact_version_stays_exact() {
        let intent = infer_intent_from_saved_spec("9.24.0");
        assert!(matches!(intent, UserSaveIntent::Exact(v) if v == "9.24.0"));
    }

    #[test]
    fn infer_intent_wildcard_stays_wildcard() {
        let intent = infer_intent_from_saved_spec("*");
        assert!(matches!(intent, UserSaveIntent::Wildcard));
    }

    #[test]
    fn short_name_strips_scope_for_global_install() {
        assert_eq!(short_name("@lpm.dev/owner.tool"), "owner.tool");
        assert_eq!(short_name("eslint"), "eslint");
    }

    /// Audit High (M3.4 round): the lost-update guard. Snapshot match
    /// must be strict on the load-bearing fields, with a clear diff
    /// message on mismatch so the user can see what changed under them.
    #[test]
    fn active_matches_planned_snapshot_passes_when_load_bearing_fields_agree() {
        let active = lpm_global::PackageEntry {
            saved_spec: "^9".into(),
            resolved: "9.24.0".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/eslint@9.24.0".into(),
            commands: vec!["eslint".into()],
        };
        // Snapshot matches on every load-bearing field. installed_at
        // and commands are intentionally NOT part of the comparison.
        let snapshot = serde_json::json!({
            "saved_spec": "^9",
            "resolved": "9.24.0",
            "integrity": "sha512-x",
            "source": "upstream-npm",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": "installs/eslint@9.24.0",
            "commands": ["DIFFERENT-COMMANDS-IGNORED"],
        });
        assert!(active_matches_planned_snapshot(&active, &snapshot).is_ok());
    }

    #[test]
    fn active_matches_planned_snapshot_detects_resolved_change() {
        let active = lpm_global::PackageEntry {
            saved_spec: "^9".into(),
            resolved: "9.25.0".into(), // bumped under us
            integrity: "sha512-newer".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/eslint@9.25.0".into(),
            commands: vec!["eslint".into()],
        };
        let snapshot = serde_json::json!({
            "saved_spec": "^9",
            "resolved": "9.24.0",
            "integrity": "sha512-x",
            "source": "upstream-npm",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": "installs/eslint@9.24.0",
            "commands": ["eslint"],
        });
        let err = active_matches_planned_snapshot(&active, &snapshot).unwrap_err();
        assert!(err.contains("resolved version changed"));
        assert!(err.contains("9.24.0"));
        assert!(err.contains("9.25.0"));
    }

    #[test]
    fn active_matches_planned_snapshot_detects_source_change() {
        let active = lpm_global::PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/x@1.0.0".into(),
            commands: vec![],
        };
        let snapshot = serde_json::json!({
            "saved_spec": "^1",
            "resolved": "1.0.0",
            "integrity": "sha512-x",
            "source": "lpm-dev",
            "installed_at": "2026-04-15T00:00:00Z",
            "root": "installs/x@1.0.0",
            "commands": [],
        });
        let err = active_matches_planned_snapshot(&active, &snapshot).unwrap_err();
        assert!(err.contains("source changed"));
    }

    /// Build a snapshot JSON that matches the provided PackageEntry
    /// on every load-bearing field. Used by the SaveSpecRewrite tests
    /// so they only have to describe the pre-plan state once.
    fn snapshot_of(entry: &lpm_global::PackageEntry) -> serde_json::Value {
        serde_json::json!({
            "saved_spec": entry.saved_spec,
            "resolved": entry.resolved,
            "integrity": entry.integrity,
            "source": serde_json::to_value(entry.source).unwrap(),
            "installed_at": entry.installed_at.to_rfc3339(),
            "root": entry.root,
            "commands": entry.commands,
        })
    }

    /// Audit Medium (M3.4 round): saved_spec rewrite must succeed even
    /// when the resolved version is unchanged. Pre-fix, planning
    /// returned AlreadyCurrent before computing new_saved_spec, so the
    /// user could not relax an exact pin without a version bump.
    #[test]
    fn execute_saved_spec_rewrite_changes_persisted_saved_spec_under_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let entry = lpm_global::PackageEntry {
            saved_spec: "3.8.3".into(),
            resolved: "3.8.3".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/prettier@3.8.3".into(),
            commands: vec!["prettier".into()],
        };
        let snapshot = snapshot_of(&entry);
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert("prettier".into(), entry);
        lpm_global::write_for(&root, &manifest).unwrap();

        execute_saved_spec_rewrite(&root, "prettier", "3.8.3", "^3", &snapshot).unwrap();

        let read_back = lpm_global::read_for(&root).unwrap();
        assert_eq!(
            read_back.packages.get("prettier").unwrap().saved_spec,
            "^3",
            "saved_spec should be rewritten without a version change"
        );
        // The resolved version stays the same — this is a manifest-only
        // mutation, not a real upgrade.
        assert_eq!(
            read_back.packages.get("prettier").unwrap().resolved,
            "3.8.3"
        );
    }

    #[test]
    fn execute_saved_spec_rewrite_refuses_when_old_spec_does_not_match() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        // Planned-against snapshot: saved_spec was "3.8.3"
        let planned = lpm_global::PackageEntry {
            saved_spec: "3.8.3".into(),
            resolved: "3.8.3".into(),
            integrity: "sha512-x".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/prettier@3.8.3".into(),
            commands: vec!["prettier".into()],
        };
        let snapshot = snapshot_of(&planned);

        // On-disk reality: someone else already retuned the saved_spec.
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert(
            "prettier".into(),
            lpm_global::PackageEntry {
                saved_spec: "^4".into(),
                resolved: "4.0.0".into(),
                integrity: "sha512-x".into(),
                source: lpm_global::PackageSource::UpstreamNpm,
                installed_at: chrono::Utc::now(),
                root: "installs/prettier@4.0.0".into(),
                commands: vec!["prettier".into()],
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let err =
            execute_saved_spec_rewrite(&root, "prettier", "3.8.3", "^3", &snapshot).unwrap_err();
        assert!(format!("{err}").contains("modified by another process"));
        assert!(format!("{err}").contains("saved_spec changed"));
    }

    /// Audit Medium (M3.4 audit pass-2): the SaveSpecRewrite prior_snapshot
    /// must guard the WHOLE row, not just saved_spec. Pre-fix the rewrite
    /// only checked that saved_spec equalled `old_saved_spec`. If another
    /// process committed an upgrade between plan and rewrite that happened
    /// to leave saved_spec alone (e.g. bulk update resolved ^3 → 3.8.4),
    /// the rewrite would cheerfully "retune" the now-3.8.4 row with the
    /// stale plan that was drafted for 3.8.3.
    ///
    /// Scenario encoded below:
    ///   plan   : active = prettier 3.8.3, saved_spec ^3; user typed `pkg@3.8.3`
    ///   disk   : concurrent bulk update landed — resolved is now 3.8.4
    ///            (saved_spec stays ^3)
    ///   expect : rewrite refuses; the now-3.8.4 row is untouched.
    #[test]
    fn execute_saved_spec_rewrite_refuses_when_resolved_changed_under_us() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());

        let planned = lpm_global::PackageEntry {
            saved_spec: "^3".into(),
            resolved: "3.8.3".into(),
            integrity: "sha512-old".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/prettier@3.8.3".into(),
            commands: vec!["prettier".into()],
        };
        let snapshot = snapshot_of(&planned);

        // On-disk reality: concurrent upgrade landed 3.8.3 → 3.8.4.
        // saved_spec is still "^3" — pre-fix this race was invisible to
        // the rewrite path.
        let upgraded = lpm_global::PackageEntry {
            saved_spec: "^3".into(),
            resolved: "3.8.4".into(),
            integrity: "sha512-new".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            installed_at: chrono::Utc::now(),
            root: "installs/prettier@3.8.4".into(),
            commands: vec!["prettier".into()],
        };
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert("prettier".into(), upgraded);
        lpm_global::write_for(&root, &manifest).unwrap();

        // User typed `lpm global update prettier@3.8.3` to pin to exact.
        let err =
            execute_saved_spec_rewrite(&root, "prettier", "^3", "3.8.3", &snapshot).unwrap_err();
        assert!(
            format!("{err}").contains("modified by another process"),
            "expected lost-update error, got: {err}"
        );
        assert!(
            format!("{err}").contains("resolved version changed"),
            "error must name the specific field that drifted: {err}"
        );

        // The now-3.8.4 row must be untouched — no "retune" applied.
        let read_back = lpm_global::read_for(&root).unwrap();
        let row = read_back.packages.get("prettier").unwrap();
        assert_eq!(row.saved_spec, "^3");
        assert_eq!(row.resolved, "3.8.4");
        assert_eq!(row.integrity, "sha512-new");
    }

    #[test]
    fn execute_saved_spec_rewrite_errors_when_package_uninstalled() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        lpm_global::write_for(&root, &lpm_global::GlobalManifest::default()).unwrap();
        // Any snapshot — the existence check runs first.
        let snapshot = serde_json::json!({});
        let err = execute_saved_spec_rewrite(&root, "ghost", "x", "y", &snapshot).unwrap_err();
        assert!(format!("{err}").contains("no longer installed"));
    }

    /// Audit Medium (M3.4 audit pass-2): in --json mode the failure path
    /// must return `LpmError::ExitCode(_)` rather than `LpmError::Script(_)`.
    /// `emit_results` has already written a structured failure JSON
    /// document to stdout; `LpmError::Script` causes main.rs to emit a
    /// second top-level `{"success": false, "error": ...}` document,
    /// breaking the single-JSON-document contract. ExitCode is the
    /// explicit "I've already emitted my own output, just propagate
    /// status" signal the top-level handler honours.
    #[tokio::test]
    async fn run_json_failure_returns_exit_code_not_script_error() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = scoped_update_env(tmp.path(), Some("http://127.0.0.1:1"));
        // Seed a manifest with a package whose saved_spec is unparseable
        // by the registry. `plan_upgrade` will fetch metadata for it —
        // we don't have a mock registry here, so registry failure
        // becomes a PlanError, which emit_results maps to a Failed
        // result. That's enough to exercise the failure-exit path.
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert(
            "this-package-should-not-exist-on-any-registry-xyz123".into(),
            lpm_global::PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: lpm_global::PackageSource::UpstreamNpm,
                installed_at: chrono::Utc::now(),
                root: "installs/ghost@1.0.0".into(),
                commands: vec![],
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        // Point registry at an unreachable host so the metadata fetch
        // fails quickly without hitting the real registry in CI.
        let r = run(None, false, true).await;

        let err = r.expect_err("json failure path must return Err");
        assert!(
            matches!(err, LpmError::ExitCode(1)),
            "json-mode failure must surface as ExitCode(1) to preserve \
             single-JSON-document contract, got: {err:?}"
        );
    }
}
