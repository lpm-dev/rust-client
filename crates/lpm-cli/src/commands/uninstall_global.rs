//! `lpm uninstall -g <pkg>` and `lpm global remove <pkg>` — phase 37
//! M3.3 persistent uninstall pipeline.
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
//!    Persist manifest (BEFORE the WAL Commit append, per the M3.1
//!    ordering invariant).
//! 5. Best-effort delete the install root. On Windows this can fail
//!    if a tool the user was running locked a file inside it; the
//!    tombstone keeps the cleanup retry alive for `store gc`.
//! 6. Append WAL Commit. Release lock.
//!
//! Note: M3.3 does not yet prune `build-state.json` /
//! `trusted-dependencies.json` entries scoped to the package — those
//! files don't exist until M5 (approve-builds --global). When M5
//! lands, this pipeline picks up the pruning step between 4 and 5.

use crate::output;
use chrono::Utc;
use lpm_common::{LpmError, LpmRoot, with_exclusive_lock};
use lpm_global::{
    AliasEntry, IntentPayload, PackageEntry, TxKind, WalRecord, WalWriter, read_for, remove_shim,
    write_for,
};
use owo_colors::OwoColorize;
use std::path::PathBuf;

pub async fn run(package: &str, json_output: bool) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    let result = with_exclusive_lock(root.global_tx_lock(), || run_under_lock(&root, package))?;
    print_success(&result, json_output);
    Ok(())
}

fn run_under_lock(root: &LpmRoot, package: &str) -> Result<UninstallOutcome, LpmError> {
    let mut manifest = read_for(root)?;

    let active = match manifest.packages.get(package).cloned() {
        Some(a) => a,
        None => {
            return Err(LpmError::Script(format!(
                "'{package}' is not globally installed. Run `lpm global list` to see what is."
            )));
        }
    };
    if manifest.pending.contains_key(package) {
        return Err(LpmError::Script(format!(
            "'{package}' has an in-flight install. Wait for it to finish (or fail) before \
             uninstalling."
        )));
    }

    let owned_aliases: Vec<(String, AliasEntry)> = manifest
        .aliases
        .iter()
        .filter(|(_, e)| e.package == package)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let install_root_abs = root.global_root().join(&active.root);
    let tx_id = mk_tx_id();

    // ─── Step 1: write Intent ──────────────────────────────────────
    let mut wal = WalWriter::open(root.global_wal())?;
    let intent =
        build_uninstall_intent(&tx_id, package, &install_root_abs, &active, &owned_aliases);
    wal.append(&intent)?;

    // ─── Step 2: remove shims (commands + aliases) ─────────────────
    let bin_dir = root.bin_dir();
    for cmd in &active.commands {
        // Best-effort but log failures. A failure here means the
        // shim file existed but couldn't be removed (permissions,
        // EBUSY); recovery will retry on next invocation.
        if let Err(e) = remove_shim(&bin_dir, cmd) {
            tracing::warn!("uninstall -g: could not remove shim '{cmd}': {e}");
        }
    }
    for (alias_name, _) in &owned_aliases {
        if let Err(e) = remove_shim(&bin_dir, alias_name) {
            tracing::warn!("uninstall -g: could not remove alias shim '{alias_name}': {e}");
        }
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
    if install_root_abs.exists()
        && let Err(e) = std::fs::remove_dir_all(&install_root_abs)
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
    // (not in M3, but the WAL contract assumes the snapshot is
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
    output::success(&format!(
        "Uninstalled {}@{}",
        out.package.bold(),
        out.version.dimmed()
    ));
    if !out.commands.is_empty() {
        output::info(&format!(
            "Removed command{}: {}",
            if out.commands.len() == 1 { "" } else { "s" },
            out.commands.join(", ")
        ));
    }
    if !out.aliases.is_empty() {
        output::info(&format!(
            "Removed alias{}: {}",
            if out.aliases.len() == 1 { "" } else { "es" },
            out.aliases.join(", ")
        ));
    }
    if out.install_root_remaining {
        output::warn(&format!(
            "Install root could not be removed (locked or permission). Queued as tombstone for `lpm store gc` to retry: {}",
            out.install_root.display()
        ));
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
}
