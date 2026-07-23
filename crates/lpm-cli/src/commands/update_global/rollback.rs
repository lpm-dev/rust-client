use super::prepare::{StagedUpgrade, UpgradePrep};
use chrono::Utc;
use lpm_common::{LpmError, LpmRoot};
use lpm_global::{GlobalManifest, Shim, WalRecord, WalWriter, emit_shim, remove_shim, write_for};
use std::collections::{HashMap, HashSet};

/// Restore shims to point at the prior install root after an upgrade
/// reaches the post-emit-but-pre-commit failure path.
///
/// For each emitted shim name:
///   - If it was a direct bin in the prior version → re-emit pointing
///     at the prior install_bin/<name>.
///   - If it was a prior alias key → re-emit pointing at the prior
///     install_bin/<alias.bin>.
///   - Otherwise (net-new shim from the upgrade) → remove it.
///
/// Returns `Err(Vec<String>)` listing names whose restore/remove
/// failed. The caller must NOT write WAL Abort in that case; recovery
/// will retry the rollback on the next `lpm` invocation.
pub(super) fn restore_prior_shims_after_aborted_upgrade(
    root: &LpmRoot,
    emitted_shims: &[String],
    prep: &UpgradePrep,
) -> Result<(), Vec<String>> {
    let bin_dir = root.bin_dir();
    let prior_root_relative = prep
        .prior_active_row_json
        .get("root")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let prior_install_bin = root
        .global_root()
        .join(prior_root_relative)
        .join("node_modules")
        .join(".bin");
    let prior_commands: HashSet<&str> = prep
        .prior_active_row_json
        .get("commands")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let prior_aliases: HashMap<&str, &str> = prep
        .prior_aliases_json
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| {
                    v.get("bin")
                        .and_then(|b| b.as_str())
                        .map(|b| (k.as_str(), b))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut failures: Vec<String> = Vec::new();
    for name in emitted_shims {
        if prior_commands.contains(name.as_str()) {
            let target = prior_install_bin.join(name);
            if let Err(e) = emit_shim(
                &bin_dir,
                &Shim {
                    command_name: name.clone(),
                    target,
                },
            ) {
                failures.push(format!("restore direct {name}: {e}"));
            }
        } else if let Some(bin) = prior_aliases.get(name.as_str()) {
            let target = prior_install_bin.join(bin);
            if let Err(e) = emit_shim(
                &bin_dir,
                &Shim {
                    command_name: name.clone(),
                    target,
                },
            ) {
                failures.push(format!("restore alias {name}: {e}"));
            }
        } else if let Err(e) = remove_shim(&bin_dir, name) {
            failures.push(format!("remove new {name}: {e}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

pub(super) fn rollback_aborted_upgrade(
    root: &LpmRoot,
    manifest: &mut GlobalManifest,
    staged: &StagedUpgrade,
    package: &str,
    reason: &str,
) -> Result<(), LpmError> {
    // Tombstone pattern: don't try to remove
    // the install root inline (could be locked on Windows by a tool
    // the user is running). Tombstone it for `store gc`.
    let install_root_ext = lpm_common::as_extended_path(&staged.install_root);
    if install_root_ext.exists()
        && let Err(e) = std::fs::remove_dir_all(&install_root_ext)
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

#[cfg(all(test, unix))]
mod tests {
    use super::super::test_support::make_complete_install_root;
    use super::*;
    use lpm_semver::Version;
    /// Post-emit rollback restores prior shim targets or removes net-new shims.
    #[test]
    #[cfg(unix)]
    fn restore_prior_shims_re_points_direct_bins_at_prior_install_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());

        let prior_root = root.install_root_for("foo", "1.0.0");
        std::fs::create_dir_all(&prior_root).unwrap();
        make_complete_install_root(&prior_root, &["pkg"]);

        // New install root that the upgrade was emitting shims against.
        let new_root = root.install_root_for("foo", "2.0.0");
        std::fs::create_dir_all(&new_root).unwrap();
        make_complete_install_root(&new_root, &["pkg", "newcmd"]);

        // Emitted shims pointing at the NEW root (the pre-rollback state).
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        std::os::unix::fs::symlink(
            new_root.join("node_modules/.bin/pkg"),
            root.bin_dir().join("pkg"),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            new_root.join("node_modules/.bin/newcmd"),
            root.bin_dir().join("newcmd"),
        )
        .unwrap();

        let prep = UpgradePrep {
            name: "foo".into(),
            current_version: "1.0.0".into(),
            new_version: Version::parse("2.0.0").unwrap(),
            new_saved_spec: "^2".into(),
            new_integrity: "sha512-new".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            prior_active_row_json: serde_json::json!({
                "saved_spec": "^1",
                "resolved": "1.0.0",
                "integrity": "sha512-old",
                "source": "upstream-npm",
                "installed_at": "2026-04-15T00:00:00Z",
                "root": "installs/foo@1.0.0",
                "commands": ["pkg"],
            }),
            prior_aliases_json: serde_json::json!({}),
        };

        restore_prior_shims_after_aborted_upgrade(
            &root,
            &["pkg".to_string(), "newcmd".to_string()],
            &prep,
        )
        .unwrap();

        // `pkg` was in prior_commands — restored to point at prior root.
        let pkg_target = std::fs::read_link(root.bin_dir().join("pkg")).unwrap();
        assert_eq!(pkg_target, prior_root.join("node_modules/.bin/pkg"));
        // `newcmd` was net-new — removed entirely.
        assert!(
            std::fs::symlink_metadata(root.bin_dir().join("newcmd")).is_err(),
            "net-new shim must be removed by rollback"
        );
    }

    /// Aliases the prior version owned are restored to the prior install root.
    #[test]
    #[cfg(unix)]
    fn restore_prior_shims_re_points_aliases_at_prior_install_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());

        let prior_root = root.install_root_for("foo", "1.0.0");
        std::fs::create_dir_all(&prior_root).unwrap();
        make_complete_install_root(&prior_root, &["dangerous"]);

        let new_root = root.install_root_for("foo", "2.0.0");
        std::fs::create_dir_all(&new_root).unwrap();
        make_complete_install_root(&new_root, &["dangerous"]);

        // `safe-name` shim was atomically re-pointed at the NEW root
        // before the artifacts_complete check failed.
        std::fs::create_dir_all(root.bin_dir()).unwrap();
        std::os::unix::fs::symlink(
            new_root.join("node_modules/.bin/dangerous"),
            root.bin_dir().join("safe-name"),
        )
        .unwrap();

        let prep = UpgradePrep {
            name: "foo".into(),
            current_version: "1.0.0".into(),
            new_version: Version::parse("2.0.0").unwrap(),
            new_saved_spec: "^2".into(),
            new_integrity: "sha512-new".into(),
            source: lpm_global::PackageSource::UpstreamNpm,
            prior_active_row_json: serde_json::json!({
                "saved_spec": "^1",
                "resolved": "1.0.0",
                "integrity": "sha512-old",
                "source": "upstream-npm",
                "installed_at": "2026-04-15T00:00:00Z",
                "root": "installs/foo@1.0.0",
                "commands": [],
            }),
            prior_aliases_json: serde_json::json!({
                "safe-name": {"package": "foo", "bin": "dangerous"}
            }),
        };

        restore_prior_shims_after_aborted_upgrade(&root, &["safe-name".to_string()], &prep)
            .unwrap();

        let safe_target = std::fs::read_link(root.bin_dir().join("safe-name")).unwrap();
        assert_eq!(
            safe_target,
            prior_root.join("node_modules/.bin/dangerous"),
            "alias shim must be restored to point at prior install root"
        );
    }
}
