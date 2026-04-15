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
            UpgradePlan::Upgrade(prep) => match execute_upgrade(&root, &registry, prep).await {
                Ok(out) => results.push(UpgradeResult::Upgraded(out)),
                Err(e) => results.push(UpgradeResult::Failed {
                    package: e.0,
                    reason: e.1.to_string(),
                }),
            },
            UpgradePlan::AlreadyCurrent { package, version } => {
                results.push(UpgradeResult::AlreadyCurrent { package, version });
            }
            UpgradePlan::PlanError { package, reason } => {
                results.push(UpgradeResult::Failed { package, reason });
            }
        }
    }

    emit_results(&results, json_output);
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
    Upgrade(Box<UpgradePrep>),
    AlreadyCurrent { package: String, version: String },
    PlanError { package: String, reason: String },
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

    // Already current? Compare resolved versions strictly.
    if new_version.to_string() == active.resolved {
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

    let new_saved_spec = decide_saved_dependency_spec(
        &intent,
        &new_version,
        SaveFlags::default(),
        SaveConfig::default(),
    )?
    .spec_to_write;

    let prior_active_row_json = serde_json::json!({
        "saved_spec": active.saved_spec,
        "resolved": active.resolved,
        "integrity": active.integrity,
        "source": serde_json::to_value(active.source).unwrap(),
        "installed_at": active.installed_at.to_rfc3339(),
        "root": active.root,
        "commands": active.commands,
    });
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
    AlreadyCurrent { package: String, version: String },
    Failed { package: String, reason: String },
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
) -> Result<UpgradeOutput, (String, LpmError)> {
    // Step 1: prepare under .tx.lock
    let staged = with_exclusive_lock(root.global_tx_lock(), || {
        prepare_upgrade_locked(root, &prep)
    })
    .map_err(|e| (prep.name.clone(), e))?;

    // Step 2: slow install (no lock)
    if let Err(e) = do_install_upgrade(registry, &prep, &staged).await {
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
    if !manifest.packages.contains_key(&prep.name) {
        return Err(LpmError::Script(format!(
            "'{}' is no longer installed (someone else uninstalled it). Aborting upgrade.",
            prep.name
        )));
    }
    if manifest.pending.contains_key(&prep.name) {
        return Err(LpmError::Script(format!(
            "'{}' has another in-flight transaction. Wait for it to finish.",
            prep.name
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
    let mut any_upgrade = false;
    for plan in plans {
        match plan {
            UpgradePlan::Upgrade(prep) => {
                any_upgrade = true;
                println!(
                    "  {} {} \u{2192} {}",
                    prep.name.bold(),
                    prep.current_version.dimmed(),
                    prep.new_version.to_string().green()
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
    if !any_upgrade {
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
}
