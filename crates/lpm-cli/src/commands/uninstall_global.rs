//! `lpm uninstall -g <pkg>` and `lpm global remove <pkg>` — persistent uninstall pipeline.
//!
//! Both surfaces dispatch here. The work is structured as a single
//! `.tx.lock`-protected transaction (uninstall has no slow phase to
//! split out the way install does). All steps are idempotent so
//! recovery can replay any prefix of them safely.
//!
//! ## Transaction shape
//!
//! 1. Acquire `.tx.lock`. Read manifest. Error if `[packages.<pkg>]`
//!    isn't present (nothing to uninstall) or `[pending.<pkg>]` is in
//!    flight (let the install commit / its rollback resolve first).
//! 2. Snapshot the prior active row (commands, root, alias entries).
//!    Append WAL Intent { kind: Uninstall, prior_active_row_json,
//!    prior_command_ownership_json } so recovery can finish what we
//!    started even after a partial crash.
//! 3. Remove every shim the package owned (commands AND aliases). The
//!    shim removal is the user-visible commit point — once a shim is
//!    gone, the user's shell can no longer resolve the command.
//! 4. Drop `[packages.<pkg>]` and every `[aliases.*]` row pointing at
//!    this package. Push the install root to `manifest.tombstones`.
//!    Persist manifest (BEFORE the WAL Commit append, per the
//!    ordering invariant).
//! 5. Best-effort delete the install root. On Windows this can fail
//!    if a tool the user was running locked a file inside it; the
//!    tombstone keeps the cleanup retry alive for `store gc`.
//! 6. Append WAL Commit. Release lock.
//!
//! Note: `build-state.json` / `trusted-dependencies.json` entries scoped to
//! the package are pruned as part of approve-scripts --global support,
//! between steps 4 and 5 above.

use crate::output;
use chrono::Utc;
use lpm_common::color::Painted;
use lpm_common::{LpmError, LpmRoot, sanitize_for_terminal, with_exclusive_lock};
use lpm_global::{
    AliasEntry, IntentPayload, PackageEntry, Shim, TxKind, WalRecord, WalWriter, emit_shim,
    read_for, remove_shim, write_for,
};
use std::path::PathBuf;

pub async fn run(package: &str, json_output: bool) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    let result = with_exclusive_lock(root.global_tx_lock(), || run_under_lock(&root, package))?;

    // Opportunistic tombstone sweep. Uninstall commit
    // just appended the install root to `manifest.tombstones`; a
    // non-blocking sweep here clears it in the common case (no file
    // locks held). If a Windows-locked file delays it, the next global
    // command's sweep retries.
    crate::commands::global::run_opportunistic_sweep(&root);

    print_success(&result, json_output);
    Ok(())
}

fn run_under_lock(root: &LpmRoot, package: &str) -> Result<UninstallOutcome, LpmError> {
    let mut manifest = read_for(root)?;

    let active = match manifest.packages.get(package).cloned() {
        Some(a) => a,
        None => {
            let package_safe = sanitize_for_terminal(package);
            return Err(LpmError::Script(format!(
                "'{package_safe}' is not globally installed. Run `lpm global list` to see what is."
            )));
        }
    };
    if manifest.pending.contains_key(package) {
        let package_safe = sanitize_for_terminal(package);
        return Err(LpmError::Script(format!(
            "'{package_safe}' has an in-flight install. Wait for it to finish (or fail) before \
             uninstalling."
        )));
    }

    let owned_aliases: Vec<(String, AliasEntry)> = manifest
        .aliases
        .iter()
        .filter(|(_, e)| e.package == package)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    // L47: validate the manifest-supplied relative install root against
    // the same `installs/<name>@<version>` shape the tombstone sweeper
    // enforces, BEFORE joining + the eventual `remove_dir_all`. A
    // poisoned `active.root` of `"."`, `"installs"`, `"../escape"`, or
    // an absolute path is refused here rather than walking outside the
    // global tree at the inline cleanup step below.
    let install_root_abs = match lpm_global::validated_install_root_relative(
        &root.global_root(),
        &active.root,
    ) {
        Ok(abs) => abs,
        Err(reason) => {
            return Err(LpmError::Script(format!(
                "uninstall of '{}' refused: install-root path {:?} is structurally invalid \
                     ({reason}). The manifest may be poisoned — inspect ~/.lpm/global/manifest.toml \
                     before retrying.",
                sanitize_for_terminal(package),
                sanitize_for_terminal(&active.root),
            )));
        }
    };
    let tx_id = mk_tx_id();

    // ─── Step 1: write Intent ──────────────────────────────────────
    let mut wal = WalWriter::open(root.global_wal())?;
    let intent =
        build_uninstall_intent(&tx_id, package, &install_root_abs, &active, &owned_aliases);
    wal.append(&intent)?;

    // ─── Step 2: remove shims (commands + aliases) ─────────────────
    //
    // Shim removal is the user-visible commit point. Each removal
    // already retries-with-backoff on Windows transient locks (see
    // `lpm-global::shim::remove_shim`). If anything still fails after
    // the retries, the package would end up "uninstalled per the
    // manifest but still resolvable via PATH" — silent inconsistency
    // (audit Medium from the audit). Track failures, restore any
    // shims we already removed (point them back at the install root,
    // which still exists at this point), then write WAL Abort and
    // surface a clear error.
    let bin_dir = root.bin_dir();
    let install_bin = install_root_abs.join("node_modules").join(".bin");
    let mut removed_command_shims: Vec<String> = Vec::new();
    let mut removed_alias_shims: Vec<(String, String)> = Vec::new(); // (alias_name, bin)
    let mut shim_failures: Vec<String> = Vec::new();

    for cmd in &active.commands {
        let result = remove_shim(&bin_dir, cmd);
        classify_command_removal(cmd, result, &mut removed_command_shims, &mut shim_failures);
    }
    for (alias_name, alias_entry) in &owned_aliases {
        let result = remove_shim(&bin_dir, alias_name);
        classify_alias_removal(
            alias_name,
            &alias_entry.bin,
            result,
            &mut removed_alias_shims,
            &mut shim_failures,
        );
    }

    if !shim_failures.is_empty() {
        // Restore the shims we already removed so PATH resolution stays
        // consistent with the (still-unchanged) manifest.
        //
        // L50: track restoration failures and propagate them honestly.
        // Pre-fix the user always saw "any shims that were removed have
        // been restored" even when restoration also failed, and the
        // WAL Abort was written regardless — leaving PATH and manifest
        // divergent with no recovery retry. Now: if ANY restoration
        // fails, surface the failures in the error message AND skip
        // WAL Abort so recovery retries on the next `lpm` invocation.
        let mut restoration_failures: Vec<String> = Vec::new();
        for cmd in &removed_command_shims {
            let target = install_bin.join(cmd);
            if let Err(e) = emit_shim(
                &bin_dir,
                &Shim {
                    command_name: cmd.clone(),
                    target,
                },
            ) {
                tracing::warn!(
                    "uninstall -g: could not restore shim '{cmd}' after partial removal: {e}"
                );
                restoration_failures.push(format!("{cmd}: {e}"));
            }
        }
        for (alias_name, bin) in &removed_alias_shims {
            let target = install_bin.join(bin);
            if let Err(e) = emit_shim(
                &bin_dir,
                &Shim {
                    command_name: alias_name.clone(),
                    target,
                },
            ) {
                tracing::warn!(
                    "uninstall -g: could not restore alias shim '{alias_name}' after partial removal: {e}"
                );
                restoration_failures.push(format!("{alias_name} (alias): {e}"));
            }
        }
        let failures_safe: Vec<String> = shim_failures
            .iter()
            .map(|f| sanitize_for_terminal(f))
            .collect();
        let reason = format!(
            "shim removal failed for {} shim(s): {}",
            shim_failures.len(),
            failures_safe.join("; ")
        );
        let package_safe = sanitize_for_terminal(package);
        if restoration_failures.is_empty() {
            // Pure restoration success — append WAL Abort so the
            // transaction is resolved; the user can re-invoke once the
            // holding process dies.
            wal.append(&WalRecord::Abort {
                tx_id: tx_id.clone(),
                reason: reason.clone(),
                aborted_at: Utc::now(),
            })?;
            return Err(LpmError::Script(format!(
                "uninstall of '{package_safe}' failed: {reason}.\n\n\
                 The package's manifest entry was preserved and any shims that were removed have \
                 been restored. Try again after closing tools that may be holding these files \
                 (antivirus, Explorer preview on Windows, running CLI processes)."
            )));
        }
        // Restoration ALSO failed. Do NOT write WAL Abort — leave the
        // transaction unresolved so recovery picks it up on the next
        // `lpm` invocation. The manifest is also unchanged at this
        // point (we never reached step 3). The user sees an honest
        // error naming both the original failures and the restoration
        // failures.
        let restoration_safe: Vec<String> = restoration_failures
            .iter()
            .map(|f| sanitize_for_terminal(f))
            .collect();
        tracing::warn!(
            "uninstall -g: restoration also failed for '{}': {}",
            package,
            restoration_failures.join("; ")
        );
        return Err(LpmError::Script(format!(
            "uninstall of '{package_safe}' failed: {reason}.\n\n\
             Restoration of the partially-removed shims ALSO failed for {} shim(s): {}. \
             The transaction has been left in an unresolved state — the next `lpm` invocation \
             will retry the rollback via recovery. PATH may be temporarily inconsistent until \
             recovery succeeds; close any tools holding these files (antivirus, Explorer \
             preview on Windows, running CLI processes) and re-run any `lpm` command to \
             trigger recovery.",
            restoration_failures.len(),
            restoration_safe.join("; ")
        )));
    }

    // ─── Step 3: drop manifest entry + alias rows + tombstone ──────
    manifest.packages.remove(package);
    for (alias_name, _) in &owned_aliases {
        manifest.aliases.remove(alias_name);
    }
    manifest.tombstones.push(active.root.clone());

    // Persist BEFORE step 4 so that a crash leaves the manifest at
    // the post-uninstall state. The next recovery treats the
    // remaining "install root still on disk" as a tombstone-sweep
    // task (cheap), not an "incomplete uninstall" state.
    write_for(root, &manifest)?;

    // ─── Step 4: delete install root (best-effort) ─────────────────
    let mut install_root_remaining = false;
    let install_root_ext = lpm_common::as_extended_path(&install_root_abs);
    if install_root_ext.exists()
        && let Err(e) = std::fs::remove_dir_all(&install_root_ext)
    {
        tracing::debug!("uninstall -g: install root cleanup deferred to tombstone sweep: {e}");
        install_root_remaining = true;
    }

    // ─── Step 5: append WAL Commit ─────────────────────────────────
    wal.append(&WalRecord::Commit {
        tx_id: tx_id.clone(),
        committed_at: Utc::now(),
    })?;

    Ok(UninstallOutcome {
        package: package.to_string(),
        version: active.resolved.clone(),
        commands: active.commands.clone(),
        aliases: owned_aliases.iter().map(|(k, _)| k.clone()).collect(),
        install_root: install_root_abs,
        install_root_remaining,
    })
}

fn build_uninstall_intent(
    tx_id: &str,
    package: &str,
    install_root_abs: &std::path::Path,
    active: &PackageEntry,
    owned_aliases: &[(String, AliasEntry)],
) -> WalRecord {
    // Snapshot the prior state so recovery can re-attempt cleanup
    // even if it has to re-read manifest from a partially-mutated
    // state. `prior_active_row_json` carries enough to identify the
    // owned commands; `prior_command_ownership_json` carries the
    // alias rows we'll be removing so a future "undo this uninstall"
    // (future "undo" support, but the WAL contract assumes the snapshot is
    // complete) could restore them.
    let prior_active_row = serde_json::json!({
        "saved_spec": active.saved_spec,
        "resolved": active.resolved,
        "integrity": active.integrity,
        "source": serde_json::to_value(active.source).unwrap(),
        "installed_at": active.installed_at.to_rfc3339(),
        "root": active.root,
        "commands": active.commands,
    });
    let alias_snapshot: serde_json::Map<String, serde_json::Value> = owned_aliases
        .iter()
        .map(|(name, entry)| {
            (
                name.clone(),
                serde_json::json!({"package": entry.package, "bin": entry.bin}),
            )
        })
        .collect();

    WalRecord::Intent(Box::new(IntentPayload {
        tx_id: tx_id.to_string(),
        kind: TxKind::Uninstall,
        package: package.to_string(),
        new_root_path: install_root_abs.to_path_buf(),
        new_row_json: serde_json::Value::Null,
        prior_active_row_json: Some(prior_active_row),
        prior_command_ownership_json: serde_json::json!({
            "aliases": serde_json::Value::Object(alias_snapshot),
        }),
        new_aliases_json: serde_json::Value::Null,
        // Uninstall never resolves collisions — it only removes state.
        // the ownership_delta is reserved for install/upgrade.
        ownership_delta: Vec::new(),
    }))
}

#[derive(Debug, Clone)]
struct UninstallOutcome {
    package: String,
    version: String,
    commands: Vec<String>,
    aliases: Vec<String>,
    install_root: PathBuf,
    install_root_remaining: bool,
}

fn print_success(out: &UninstallOutcome, json_output: bool) {
    if json_output {
        let body = serde_json::json!({
            "success": true,
            "package": out.package,
            "version": out.version,
            "commands_removed": out.commands,
            "aliases_removed": out.aliases,
            "install_root": out.install_root.display().to_string(),
            "install_root_remaining": out.install_root_remaining,
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
        return;
    }
    let package_safe = sanitize_for_terminal(&out.package);
    let version_safe = sanitize_for_terminal(&out.version);
    output::success(&format!(
        "Uninstalled {}@{}",
        package_safe.bold(),
        version_safe.dimmed()
    ));
    if !out.commands.is_empty() {
        let commands_safe: Vec<String> = out
            .commands
            .iter()
            .map(|c| sanitize_for_terminal(c))
            .collect();
        output::info(&format!(
            "Removed command{}: {}",
            if out.commands.len() == 1 { "" } else { "s" },
            commands_safe.join(", ")
        ));
    }
    if !out.aliases.is_empty() {
        let aliases_safe: Vec<String> = out
            .aliases
            .iter()
            .map(|a| sanitize_for_terminal(a))
            .collect();
        output::info(&format!(
            "Removed alias{}: {}",
            if out.aliases.len() == 1 { "" } else { "es" },
            aliases_safe.join(", ")
        ));
    }
    if out.install_root_remaining {
        let root_safe = sanitize_for_terminal(&out.install_root.display().to_string());
        output::warn(&format!(
            "Install root could not be removed (locked or permission). Queued as tombstone for `lpm cache prune --apply` to retry: {root_safe}"
        ));
    }
}

/// Classify the result of a per-command shim removal so the abort path
/// can correctly restore partial state.
///
/// **Why `Err` adds the command to `removed_list`:** on Windows
/// `remove_shim` walks a triple (`.cmd`, `.ps1`, bash shim) and
/// returns `Err` as soon as one artifact's unlink fails — even if
/// earlier artifacts in the same call already succeeded. Treating
/// `Err` as "shim wasn't touched" would skip restoration for a
/// command that was actually left half-removed, leaving the user with
/// "manifest says installed, PATH inconsistent" state — exactly what
/// the audit pass-2 fix set out to eliminate (audit Medium from
/// the fix round). The conservative restore (re-emit the whole
/// triple via `emit_shim`'s atomic replace) is harmless when the
/// removal completed and repairs the partial-removal case. On Unix
/// every shim is one symlink, so partial removal is impossible — but
/// the conservative branch is still correct (re-emitting an absent
/// symlink just creates it).
fn classify_command_removal(
    cmd: &str,
    result: Result<Vec<std::path::PathBuf>, lpm_global::ShimError>,
    removed_list: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    match result {
        Ok(removed) if !removed.is_empty() => removed_list.push(cmd.to_string()),
        Ok(_) => {} // shim wasn't there to begin with
        Err(e) => {
            removed_list.push(cmd.to_string());
            failures.push(format!("{cmd}: {e}"));
        }
    }
}

/// Same `Err`-tracks-as-removed contract as [`classify_command_removal`],
/// but for alias entries (which need both the alias name and the bin
/// it points at to be restorable). See that function's doc-comment.
fn classify_alias_removal(
    alias_name: &str,
    bin: &str,
    result: Result<Vec<std::path::PathBuf>, lpm_global::ShimError>,
    removed_list: &mut Vec<(String, String)>,
    failures: &mut Vec<String>,
) {
    match result {
        Ok(removed) if !removed.is_empty() => {
            removed_list.push((alias_name.to_string(), bin.to_string()));
        }
        Ok(_) => {}
        Err(e) => {
            removed_list.push((alias_name.to_string(), bin.to_string()));
            failures.push(format!("{alias_name} (alias): {e}"));
        }
    }
}

fn mk_tx_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos}-{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_common::LpmRoot;
    use lpm_global::{GlobalManifest, PackageSource, write_for};
    use tempfile::TempDir;

    fn seed_active_package(root: &LpmRoot, name: &str, commands: &[&str]) -> PathBuf {
        let install_root = root.install_root_for(name, "1.0.0");
        std::fs::create_dir_all(install_root.join("node_modules").join(".bin")).unwrap();
        let mut manifest = GlobalManifest::default();
        let active = PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-x".into(),
            source: PackageSource::LpmDev,
            installed_at: Utc::now(),
            root: format!("installs/{name}@1.0.0"),
            commands: commands.iter().map(|s| s.to_string()).collect(),
        };
        manifest.packages.insert(name.into(), active);
        write_for(root, &manifest).unwrap();
        install_root
    }

    #[test]
    fn uninstall_unknown_package_errors_with_helpful_message() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let err = run_under_lock(&root, "ghost").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not globally installed"));
        assert!(msg.contains("global list"));
    }

    #[test]
    fn uninstall_blocks_when_package_has_inflight_install() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "pkg".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "installs/pkg@1.0.0".into(),
                commands: vec![],
            },
        );
        manifest.pending.insert(
            "pkg".into(),
            lpm_global::PendingEntry {
                saved_spec: "^2".into(),
                resolved: "2.0.0".into(),
                integrity: "sha512-y".into(),
                source: PackageSource::LpmDev,
                started_at: Utc::now(),
                root: "installs/pkg@2.0.0".into(),
                commands: vec![],
                replaces_version: Some("1.0.0".into()),
            },
        );
        write_for(&root, &manifest).unwrap();
        let err = run_under_lock(&root, "pkg").unwrap_err();
        assert!(format!("{err}").contains("in-flight install"));
    }

    #[test]
    fn uninstall_drops_package_row_and_appends_wal_commit() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = seed_active_package(&root, "eslint", &["eslint"]);

        let outcome = run_under_lock(&root, "eslint").unwrap();
        assert_eq!(outcome.package, "eslint");
        assert_eq!(outcome.commands, vec!["eslint"]);

        let manifest = read_for(&root).unwrap();
        assert!(!manifest.packages.contains_key("eslint"));
        assert!(
            manifest
                .tombstones
                .iter()
                .any(|t| t == "installs/eslint@1.0.0"),
            "install root should be queued as tombstone"
        );

        // Install root deleted (best-effort succeeds in tempdir).
        assert!(!install_root.exists());

        // WAL has Intent + Commit.
        let scan = lpm_global::WalReader::at(root.global_wal()).scan().unwrap();
        assert_eq!(scan.records.len(), 2);
        assert!(matches!(scan.records[0], WalRecord::Intent(_)));
        assert!(matches!(scan.records[1], WalRecord::Commit { .. }));
    }

    #[test]
    fn uninstall_removes_alias_rows_owned_by_the_package() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed_active_package(&root, "pkg-b", &["serve"]);
        // Add an alias `srv` → pkg-b's `serve`.
        let mut manifest = read_for(&root).unwrap();
        manifest.aliases.insert(
            "srv".into(),
            AliasEntry {
                package: "pkg-b".into(),
                bin: "serve".into(),
            },
        );
        write_for(&root, &manifest).unwrap();

        let outcome = run_under_lock(&root, "pkg-b").unwrap();
        assert_eq!(outcome.aliases, vec!["srv"]);

        let final_manifest = read_for(&root).unwrap();
        assert!(!final_manifest.aliases.contains_key("srv"));
    }

    #[test]
    fn uninstall_does_not_touch_other_packages_aliases() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed_active_package(&root, "target", &["t"]);
        // Plant another package + its alias; uninstalling target must
        // leave it alone.
        let mut manifest = read_for(&root).unwrap();
        manifest.packages.insert(
            "untouched".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-y".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "installs/untouched@1.0.0".into(),
                commands: vec!["u".into()],
            },
        );
        manifest.aliases.insert(
            "u-alias".into(),
            AliasEntry {
                package: "untouched".into(),
                bin: "u".into(),
            },
        );
        write_for(&root, &manifest).unwrap();

        run_under_lock(&root, "target").unwrap();

        let final_manifest = read_for(&root).unwrap();
        assert!(final_manifest.packages.contains_key("untouched"));
        assert!(final_manifest.aliases.contains_key("u-alias"));
    }

    /// Audit Medium: the partial-Windows-triple bug.
    /// `remove_shim` returns `Err` as soon as one artifact's removal
    /// fails, even if earlier artifacts in the same call already
    /// succeeded. The caller MUST treat `Err` as "this command may be
    /// half-removed → add to restore list" or the abort path will
    /// commit a broken triple. These unit tests verify the
    /// `classify_*_removal` helpers do that.
    #[test]
    fn classify_command_removal_err_adds_command_to_restore_list() {
        // Repro of the audit's exact scenario. Pre-fix the Err case
        // would have left `removed_list` empty, skipping restoration
        // for a half-removed triple.
        let mut removed = Vec::new();
        let mut failures = Vec::new();
        classify_command_removal(
            "eslint",
            Err(lpm_global::ShimError::Io(std::io::Error::other(
                "simulated partial-triple failure",
            ))),
            &mut removed,
            &mut failures,
        );
        assert_eq!(
            removed,
            vec!["eslint".to_string()],
            "Err must add command to restore list (partial-triple invariant)"
        );
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("simulated partial-triple failure"));
    }

    #[test]
    fn classify_command_removal_ok_with_removed_files_adds_to_list() {
        let mut removed = Vec::new();
        let mut failures = Vec::new();
        classify_command_removal(
            "eslint",
            Ok(vec![std::path::PathBuf::from("/tmp/eslint")]),
            &mut removed,
            &mut failures,
        );
        assert_eq!(removed, vec!["eslint".to_string()]);
        assert!(failures.is_empty());
    }

    #[test]
    fn classify_command_removal_ok_empty_means_shim_was_absent_no_restore_needed() {
        let mut removed: Vec<String> = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        classify_command_removal("ghost", Ok(Vec::new()), &mut removed, &mut failures);
        assert!(removed.is_empty(), "absent shim doesn't need restoration");
        assert!(failures.is_empty());
    }

    #[test]
    fn classify_alias_removal_err_adds_alias_with_bin_to_restore_list() {
        let mut removed = Vec::new();
        let mut failures = Vec::new();
        classify_alias_removal(
            "srv",
            "serve",
            Err(lpm_global::ShimError::Io(std::io::Error::other("boom"))),
            &mut removed,
            &mut failures,
        );
        assert_eq!(removed, vec![("srv".to_string(), "serve".to_string())]);
        assert_eq!(failures.len(), 1);
    }

    /// Audit Medium: when shim removal fails, uninstall
    /// must NOT commit. The manifest entry stays, partially-removed
    /// shims get restored, and the user sees a clear error. Without
    /// this fix, `uninstall -g` would happily report success while
    /// the command still resolved on PATH.
    #[test]
    #[cfg(unix)]
    fn uninstall_aborts_when_shim_removal_fails_and_restores_partial_state() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        // Two-command package so we can verify partial-restore.
        seed_active_package(&root, "twocmd", &["alpha", "beta"]);
        // Plant the install root's bin entries (real files so shim
        // restore can target them).
        let install_bin = root
            .install_root_for("twocmd", "1.0.0")
            .join("node_modules")
            .join(".bin");
        std::fs::create_dir_all(&install_bin).unwrap();
        for cmd in ["alpha", "beta"] {
            std::fs::write(install_bin.join(cmd), b"#!/bin/sh\necho ok").unwrap();
            std::fs::set_permissions(
                install_bin.join(cmd),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }

        // Plant both shims in bin_dir so removal has work to do.
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        std::os::unix::fs::symlink(install_bin.join("alpha"), root.bin_dir().join("alpha"))
            .unwrap();
        std::os::unix::fs::symlink(install_bin.join("beta"), root.bin_dir().join("beta")).unwrap();

        // Drop write permission on bin_dir between the two shim
        // removals... actually simpler: drop perm before either runs.
        // Both removals fail → restoration also fails (perm drop
        // blocks symlink creation too) → error surfaces with the
        // manifest unchanged.
        let original_perms = std::fs::metadata(root.bin_dir()).unwrap().permissions();
        std::fs::set_permissions(root.bin_dir(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = run_under_lock(&root, "twocmd");

        // Restore perms before any assertion-driven panic so the
        // tempdir cleanup doesn't get stuck.
        std::fs::set_permissions(root.bin_dir(), original_perms).unwrap();

        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("uninstall of 'twocmd' failed"),
            "expected uninstall failure error, got: {err}"
        );

        // Manifest must still claim the package — uninstall didn't
        // commit.
        let manifest = read_for(&root).unwrap();
        assert!(
            manifest.packages.contains_key("twocmd"),
            "manifest entry must be preserved when uninstall fails"
        );

        // L50: when restoration ALSO fails (here the 0o555 perm on
        // bin_dir blocks both `remove_shim` AND `emit_shim`), the
        // transaction is left unresolved so recovery retries on the
        // next `lpm` invocation. Pre-fix the WAL Abort was written
        // regardless, leaving PATH and manifest divergent with no
        // recovery path. Verify the new contract: NO Abort record
        // (the unresolved Intent is the recovery handle), and the
        // error message names BOTH the removal AND restoration
        // failures so the operator knows the state is actively
        // recovering.
        let scan = lpm_global::WalReader::at(root.global_wal()).scan().unwrap();
        let has_abort = scan
            .records
            .iter()
            .any(|r| matches!(r, WalRecord::Abort { .. }));
        assert!(
            !has_abort,
            "L50: when restoration also fails, WAL Abort must be skipped \
             so recovery retries on next invocation"
        );
        let has_intent = scan
            .records
            .iter()
            .any(|r| matches!(r, WalRecord::Intent(_)));
        assert!(
            has_intent,
            "Intent must be on disk so recovery has the cleanup handle"
        );
        // Error message must surface BOTH the original removal failure
        // and the restoration failure — honest reporting per L50.
        assert!(
            format!("{err}").contains("Restoration of the partially-removed shims ALSO failed"),
            "L50: error must surface restoration failure, got: {err}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn uninstall_removes_owned_shim() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed_active_package(&root, "eslint", &["eslint"]);
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        std::os::unix::fs::symlink("/some/target", root.bin_dir().join("eslint")).unwrap();

        run_under_lock(&root, "eslint").unwrap();
        assert!(
            std::fs::symlink_metadata(root.bin_dir().join("eslint")).is_err(),
            "shim must be removed"
        );
    }

    // ─── uninstall invariant under the manifest model ──
    //
    // `PackageEntry.commands` excludes aliased-away names (manifest
    // invariant). A package installed with
    // `--alias serve=foo-serve` ends up with:
    //
    //     [packages.foo]
    //     commands = ["lint"]            (NOT ["serve", "lint"])
    //
    //     [aliases.foo-serve]
    //     package = "foo"
    //     bin = "serve"
    //
    // Uninstall iterates `active.commands` to remove direct-bin shims
    // and `manifest.aliases` (filtered by package) to remove alias
    // shims. The invariant means uninstall does NOT attempt to remove
    // a shim named `serve` (which was never written). Pin that here
    // so a future refactor can't regress.

    #[test]
    fn uninstall_under_alias_invariant_removes_aliased_name_only_not_orig() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Seed a package installed with the invariant: `foo`
        // declares [serve, lint] but serve is exposed via alias.
        let install_root = seed_active_package(&root, "foo", &["lint"]);

        // Add the foo-serve → serve alias row.
        let mut manifest = read_for(&root).unwrap();
        manifest.aliases.insert(
            "foo-serve".into(),
            AliasEntry {
                package: "foo".into(),
                bin: "serve".into(),
            },
        );
        write_for(&root, &manifest).unwrap();

        // Emit the real shim artifacts: `lint` (direct) and `foo-serve`
        // (alias). `serve` is intentionally NOT emitted — the alias
        // invariant says it shouldn't be.
        let bin_dir = root.bin_dir();
        std::fs::create_dir_all(&bin_dir).unwrap();
        let install_bin = install_root.join("node_modules").join(".bin");
        std::fs::create_dir_all(&install_bin).unwrap();
        std::fs::write(install_bin.join("lint"), b"#!/bin/sh\n").unwrap();
        std::fs::write(install_bin.join("serve"), b"#!/bin/sh\n").unwrap();
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: "lint".into(),
                target: install_bin.join("lint"),
            },
        )
        .unwrap();
        emit_shim(
            &bin_dir,
            &Shim {
                command_name: "foo-serve".into(),
                target: install_bin.join("serve"),
            },
        )
        .unwrap();

        // Sanity: `serve` shim must not exist pre-uninstall.
        assert!(
            std::fs::symlink_metadata(bin_dir.join("serve")).is_err(),
            "invariant: direct `serve` shim must never have been emitted"
        );

        // Run the uninstall — must complete cleanly even though foo
        // has a bin named `serve` that was never put on PATH.
        let outcome = run_under_lock(&root, "foo").unwrap();

        // Expected cleanup surface: direct commands (lint) + owned
        // aliases (foo-serve). NO `serve` in either list.
        assert_eq!(outcome.commands, vec!["lint"]);
        assert_eq!(outcome.aliases, vec!["foo-serve"]);

        // Both emitted shims gone.
        assert!(
            std::fs::symlink_metadata(bin_dir.join("lint")).is_err(),
            "lint shim must be removed"
        );
        assert!(
            std::fs::symlink_metadata(bin_dir.join("foo-serve")).is_err(),
            "foo-serve alias shim must be removed"
        );

        // Manifest state: foo row gone, foo-serve alias row gone.
        let final_manifest = read_for(&root).unwrap();
        assert!(!final_manifest.packages.contains_key("foo"));
        assert!(!final_manifest.aliases.contains_key("foo-serve"));
    }

    /// A manifest entry whose name carries OSC 8 hyperlink bytes or
    /// CSI cursor manipulation reaches `run` only through the
    /// `not-globally-installed` error path (the user has to type the
    /// exact same name). The error formatter still routes the supplied
    /// name through `sanitize_for_terminal` so a pasted-from-elsewhere
    /// hostile spec can't paint the operator's terminal via the error
    /// surface.
    #[test]
    fn uninstall_not_installed_error_strips_control_bytes_from_supplied_name() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let evil = "\u{1b}]8;;file:///etc/passwd\u{07}phantom\u{1b}]8;;\u{07}";
        let err = run_under_lock(&root, evil).unwrap_err();
        let msg = format!("{err}");
        assert!(!msg.contains('\u{1b}'), "ESC must be scrubbed: {msg:?}");
        assert!(!msg.contains('\u{07}'), "BEL must be scrubbed: {msg:?}");
        assert!(msg.contains("phantom"));
        assert!(msg.contains("not globally installed"));
    }

    /// L47: a manifest poisoned with a structurally invalid `active.root`
    /// (parent-traversal, absolute path, single segment) must be refused
    /// before any `remove_dir_all` walks outside the global tree. The
    /// existing tombstone sweep's `validated_install_root_relative`
    /// helper is the canonical shape check — uninstall now gates on it
    /// before computing the install-root path.
    #[test]
    fn uninstall_refuses_structurally_invalid_install_root_in_manifest() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut manifest = GlobalManifest::default();
        // Poisoned row: `root = "../escape"` would join under
        // global_root() to outside-tree if not validated.
        manifest.packages.insert(
            "evilpkg".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::LpmDev,
                installed_at: Utc::now(),
                root: "../escape".into(),
                commands: vec![],
            },
        );
        write_for(&root, &manifest).unwrap();

        let err = run_under_lock(&root, "evilpkg").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("structurally invalid")
                && msg.contains("../escape")
                && msg.contains("manifest may be poisoned"),
            "expected L47 refusal naming the structural invalid + manifest-poisoned, got: {msg}"
        );

        // Manifest unchanged — uninstall refused at the gate, the row
        // is still there.
        let after = read_for(&root).unwrap();
        assert!(after.packages.contains_key("evilpkg"));
    }
}
