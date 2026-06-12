use crate::doctor_catalog;

use super::check::Check;

// ─── global-installs health checks ─────────────────────

/// Top-level entry for the global health checks. Returns an empty Vec
/// if `~/.lpm/global/` doesn't exist (fresh machine / project-only
/// user) — doctor shouldn't invent checks for features the user hasn't
/// touched.
///
/// Each check has its own function so individual checks can be
/// unit-tested against a synthetic `LpmRoot` without running the whole
/// `doctor::run` pipeline.
pub(super) fn check_global_installs() -> Vec<Check> {
    let root = match lpm_common::LpmRoot::from_env() {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    // Nothing to check if the global tree was never created.
    if !root.global_root().exists() {
        return Vec::new();
    }

    let mut out = Vec::new();

    // 14. Manifest validity.
    out.push(check_global_manifest_validity(&root));

    // The rest only make sense if the manifest read cleanly; otherwise
    // skip to avoid cascading errors that reference a corrupt
    // manifest's rows. The `check_global_manifest_validity` check
    // already surfaces the read error.
    let Ok(manifest) = lpm_global::read_for(&root) else {
        return out;
    };

    // 15. PATH presence.
    out.push(check_bin_dir_on_path(&root));

    // 16. Orphaned bin shims.
    out.push(check_orphaned_bin_shims(&root, &manifest));

    // Shim targets: the filename check catches orphans; Unix symlink
    // target validation catches stale rollback artifacts and same-user
    // PATH hijack shapes. Windows shim triples are scripts rather than
    // symlinks, so target validation needs a format-aware parser there.
    #[cfg(unix)]
    out.push(check_global_shim_targets(&root, &manifest));

    // 17. Install-root consistency.
    out.push(check_install_root_consistency(&root, &manifest));

    // Global trusted-dependencies state. A malformed or future-schema
    // trust file can break `lpm install -g` via synthetic
    // `lpm.trustedDependencies`, and can also break
    // `lpm approve-scripts --global`.
    out.push(check_global_trusted_deps(&root));

    out
}

fn check_global_manifest_validity(root: &lpm_common::LpmRoot) -> Check {
    let path = root.global_manifest();
    if !path.exists() {
        return Check::pass(
            &doctor_catalog::GLOBAL_MANIFEST_ABSENT,
            "not present (no global installs yet)",
        );
    }
    let manifest = match lpm_global::read_for(root) {
        Ok(m) => m,
        Err(e) => {
            return Check::fail(
                &doctor_catalog::GLOBAL_MANIFEST_CORRUPT,
                &format!(
                    "{}: {e}. Fix hint: inspect the file or delete it to reset the global tree.",
                    path.display(),
                ),
            );
        }
    };

    // Structural validation beyond TOML parseability.
    //
    // Check each row's invariants the install + recovery pipelines
    // actually depend on. The TOML parser is permissive (it'll accept
    // any string for `root`); install/recovery/uninstall use the
    // `validated_install_root_relative` shape check at write
    // boundaries, so doctor surfaces a structurally-invalid manifest
    // BEFORE the next `lpm install -g` / `lpm uninstall -g` /
    // `lpm doctor --all`'s dir_size walker tries to act on it.
    //
    // Invariants:
    //   - every `packages.*.root` must pass `validated_install_root_relative`
    //   - every `aliases.<name>` must reference a package present in
    //     `packages` AND a bin declared in that package's `commands`
    //     (or the package's bin emission list — but `commands` is the
    //     post-resolution authoritative list, so we use that)
    //   - every `tombstones[]` entry must pass the same shape check
    let global_root = root.global_root();
    let mut issues: Vec<String> = Vec::new();

    for (pkg_name, entry) in &manifest.packages {
        let root_check = if entry.source == lpm_global::PackageSource::LocalLink {
            lpm_global::validated_local_link_root_relative(&global_root, &entry.root)
        } else {
            lpm_global::validated_install_root_relative(&global_root, &entry.root)
        };
        if let Err(reason) = root_check {
            issues.push(format!(
                "package '{}': root {:?} structurally invalid ({reason})",
                lpm_common::sanitize_for_terminal(pkg_name),
                lpm_common::sanitize_for_terminal(&entry.root),
            ));
        }
    }
    for (alias_name, alias_entry) in &manifest.aliases {
        let Some(owner) = manifest.packages.get(&alias_entry.package) else {
            issues.push(format!(
                "alias '{}': package '{}' is not installed (dangling alias row)",
                lpm_common::sanitize_for_terminal(alias_name),
                lpm_common::sanitize_for_terminal(&alias_entry.package),
            ));
            continue;
        };
        if !owner.commands.contains(&alias_entry.bin) {
            issues.push(format!(
                "alias '{}': bin '{}' is not declared by package '{}'",
                lpm_common::sanitize_for_terminal(alias_name),
                lpm_common::sanitize_for_terminal(&alias_entry.bin),
                lpm_common::sanitize_for_terminal(&alias_entry.package),
            ));
        }
    }
    for tombstone in &manifest.tombstones {
        if let Err(reason) = lpm_global::validated_install_root_relative(&global_root, tombstone) {
            issues.push(format!(
                "tombstone {:?} structurally invalid ({reason})",
                lpm_common::sanitize_for_terminal(tombstone),
            ));
        }
    }

    if !issues.is_empty() {
        let preview: Vec<String> = issues.iter().take(5).cloned().collect();
        let more = if issues.len() > preview.len() {
            format!(", +{} more", issues.len() - preview.len())
        } else {
            String::new()
        };
        return Check::fail(
            &doctor_catalog::GLOBAL_MANIFEST_STRUCTURALLY_INVALID,
            &format!(
                "{}: {} structural issue{} ({}{}). Fix hint: inspect the file or hand-repair the \
                 offending rows.",
                path.display(),
                issues.len(),
                if issues.len() == 1 { "" } else { "s" },
                preview.join("; "),
                more,
            ),
        );
    }

    Check::pass(
        &doctor_catalog::GLOBAL_MANIFEST_VALID,
        &format!(
            "{} package{}, {} alias{}, {} tombstone{}",
            manifest.packages.len(),
            if manifest.packages.len() == 1 {
                ""
            } else {
                "s"
            },
            manifest.aliases.len(),
            if manifest.aliases.len() == 1 {
                ""
            } else {
                "es"
            },
            manifest.tombstones.len(),
            if manifest.tombstones.len() == 1 {
                ""
            } else {
                "s"
            },
        ),
    )
}

fn check_bin_dir_on_path(root: &lpm_common::LpmRoot) -> Check {
    let bin_dir = root.bin_dir();
    let path_env = std::env::var("PATH").unwrap_or_default();
    if crate::path_onboarding::is_bin_dir_on_path_str(&bin_dir, &path_env) {
        Check::pass(
            &doctor_catalog::GLOBAL_BIN_ON_PATH,
            &bin_dir.display().to_string(),
        )
    } else {
        Check::warn(
            &doctor_catalog::GLOBAL_BIN_OFF_PATH,
            &format!(
                "{} not on PATH. Fix hint: add it to your shell init (see `lpm global bin`).",
                bin_dir.display(),
            ),
        )
    }
}

fn check_orphaned_bin_shims(
    root: &lpm_common::LpmRoot,
    manifest: &lpm_global::GlobalManifest,
) -> Check {
    let bin_dir = root.bin_dir();
    if !bin_dir.exists() {
        return Check::pass(
            &doctor_catalog::GLOBAL_SHIMS_NO_DIR,
            "bin dir does not exist yet",
        );
    }
    // A shim is a file whose stem matches a package command or alias
    // name. On Windows, any member of the triple (`.cmd`, `.ps1`, no
    // suffix) counts; on Unix just the bare name.
    let owned_names: std::collections::HashSet<String> = manifest
        .packages
        .values()
        .flat_map(|e| e.commands.iter().cloned())
        .chain(manifest.aliases.keys().cloned())
        .collect();

    let mut orphans: Vec<String> = Vec::new();
    let Ok(entries) = std::fs::read_dir(&bin_dir) else {
        return Check::warn(
            &doctor_catalog::GLOBAL_SHIMS_UNREADABLE,
            &format!("could not read {}", bin_dir.display()),
        );
    };
    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let Some(name_str) = name_os.to_str() else {
            continue;
        };
        // Derive stem: strip a single known extension if present.
        let stem = name_str
            .strip_suffix(".cmd")
            .or_else(|| name_str.strip_suffix(".ps1"))
            .unwrap_or(name_str);
        if !owned_names.contains(stem) {
            orphans.push(name_str.to_string());
        }
    }
    orphans.sort();
    orphans.dedup();

    if orphans.is_empty() {
        Check::pass(
            &doctor_catalog::GLOBAL_SHIMS_CLEAN,
            &format!(
                "{} owned shim{} in {}",
                owned_names.len(),
                if owned_names.len() == 1 { "" } else { "s" },
                bin_dir.display(),
            ),
        )
    } else {
        let preview: Vec<String> = orphans.iter().take(5).cloned().collect();
        let more = if orphans.len() > preview.len() {
            format!(", +{} more", orphans.len() - preview.len())
        } else {
            String::new()
        };
        Check::warn(
            &doctor_catalog::GLOBAL_SHIMS_ORPHANS,
            &format!(
                "{} shim{} in {} not owned by any manifest entry ({}{}). Fix hint: \
                 `lpm cache prune --apply` sweeps tombstoned roots but does not rm \
                 orphaned shims; remove manually or re-run the owning install to reclaim.",
                orphans.len(),
                if orphans.len() == 1 { "" } else { "s" },
                bin_dir.display(),
                preview.join(", "),
                more,
            ),
        )
    }
}

/// Read `~/.lpm/global/trusted-dependencies.json` and report presence,
/// approval count, and parse health. A malformed or future-schema trust
/// file breaks `lpm install -g` via the synthetic
/// `lpm.trustedDependencies` projection used by global installs, and
/// can also break `lpm approve-scripts --global`.
///
/// The check itself is small — the trust store is a few hundred
/// bytes typically — but it covers the same diagnostic gap that the
/// other "state file readable + structurally valid" checks address.
fn check_global_trusted_deps(root: &lpm_common::LpmRoot) -> Check {
    let path = root.global_trusted_deps();
    if !path.exists() {
        return Check::pass(
            &doctor_catalog::GLOBAL_TRUSTED_DEPS_ABSENT,
            "not present (no host-global approvals yet)",
        );
    }
    match lpm_global::trusted_deps::read_at(&path) {
        Ok(value) => Check::pass(
            &doctor_catalog::GLOBAL_TRUSTED_DEPS_VALID,
            &format!(
                "{} approval{}",
                value.trusted.len(),
                if value.trusted.len() == 1 { "" } else { "s" },
            ),
        ),
        Err(e) => Check::fail(
            &doctor_catalog::GLOBAL_TRUSTED_DEPS_CORRUPT,
            &format!(
                "{}: {e}. Fix hint: delete the file to reset the host-global trust list \
                 (operators re-approve on next `lpm install -g` or `lpm approve-scripts --global`).",
                path.display(),
            ),
        ),
    }
}

/// Verify each manifest-owned shim in `~/.lpm/bin` is a symlink pointing
/// at the expected `<install-root>/node_modules/.bin/<bin>`.
///
/// Unix-only — Windows shim artifacts are `.cmd`/`.ps1`/bash-shim
/// scripts that exec the target via a baked-in path string, so
/// verifying them needs a parser per shim format. The orphaned-filename
/// check already covers the stale-artifact-by-name shape on Windows.
///
/// What "wrong target" means here:
///   - file exists at the expected path but is NOT a symlink (a
///     regular-file replacement is the same-user PATH-hijack shape)
///   - symlink target doesn't match the manifest-expected path
///     (stale rollback artifact pointing at a deleted install root,
///     or a same-user-tampered symlink pointing elsewhere entirely)
///   - shim is missing entirely (manifest says it should exist but
///     `~/.lpm/bin/<name>` doesn't — partial rollback or external
///     deletion)
///
/// Returns a single `Check` so the pass/warn shape matches the rest
/// of the doctor surface. Mismatches list up to 5 names so JSON
/// consumers can drill in.
#[cfg(unix)]
fn check_global_shim_targets(
    root: &lpm_common::LpmRoot,
    manifest: &lpm_global::GlobalManifest,
) -> Check {
    let bin_dir = root.bin_dir();
    if !bin_dir.exists() {
        // No bin dir → nothing to verify. The orphaned-shim check
        // already passes in this state; we just match it.
        return Check::pass(
            &doctor_catalog::GLOBAL_SHIM_TARGETS_HEALTHY,
            "bin dir does not exist yet",
        );
    }

    let mut expectations: Vec<(String, std::path::PathBuf)> = Vec::new();
    // Direct commands: bin/<cmd> → <install-root>/node_modules/.bin/<cmd>
    for entry in manifest.packages.values() {
        let install_root = root.global_root().join(&entry.root);
        let install_bin = install_root.join("node_modules").join(".bin");
        for cmd in &entry.commands {
            expectations.push((cmd.clone(), install_bin.join(cmd)));
        }
    }
    // Aliases: bin/<alias_name> → <pkg's install-root>/node_modules/.bin/<alias.bin>
    for (alias_name, alias_entry) in &manifest.aliases {
        let Some(owner) = manifest.packages.get(&alias_entry.package) else {
            // Alias row pointing at a non-existent package is its own
            // structural problem surfaced by manifest validation. Skip
            // the target check here so we don't double-fail.
            continue;
        };
        let install_root = root.global_root().join(&owner.root);
        let install_bin = install_root.join("node_modules").join(".bin");
        expectations.push((alias_name.clone(), install_bin.join(&alias_entry.bin)));
    }

    let mut mismatches: Vec<String> = Vec::new();
    for (shim_name, expected_target) in &expectations {
        let shim_path = bin_dir.join(shim_name);
        let meta = match std::fs::symlink_metadata(&shim_path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                mismatches.push(format!(
                    "{}: shim missing (manifest expects symlink)",
                    lpm_common::sanitize_for_terminal(shim_name)
                ));
                continue;
            }
            Err(e) => {
                mismatches.push(format!(
                    "{}: cannot stat ({e})",
                    lpm_common::sanitize_for_terminal(shim_name)
                ));
                continue;
            }
        };
        if !meta.file_type().is_symlink() {
            mismatches.push(format!(
                "{}: regular file at shim path (expected symlink — possible PATH hijack)",
                lpm_common::sanitize_for_terminal(shim_name)
            ));
            continue;
        }
        match std::fs::read_link(&shim_path) {
            Ok(actual_target) => {
                if actual_target != *expected_target {
                    mismatches.push(format!(
                        "{}: symlink points at {} (expected {})",
                        lpm_common::sanitize_for_terminal(shim_name),
                        lpm_common::sanitize_for_terminal(&actual_target.display().to_string()),
                        lpm_common::sanitize_for_terminal(&expected_target.display().to_string()),
                    ));
                }
            }
            Err(e) => {
                mismatches.push(format!(
                    "{}: readlink failed ({e})",
                    lpm_common::sanitize_for_terminal(shim_name)
                ));
            }
        }
    }

    if mismatches.is_empty() {
        return Check::pass(
            &doctor_catalog::GLOBAL_SHIM_TARGETS_HEALTHY,
            &format!(
                "{} owned shim{} verified (symlink + target)",
                expectations.len(),
                if expectations.len() == 1 { "" } else { "s" },
            ),
        );
    }
    let preview: Vec<String> = mismatches.iter().take(5).cloned().collect();
    let more = if mismatches.len() > preview.len() {
        format!(", +{} more", mismatches.len() - preview.len())
    } else {
        String::new()
    };
    Check::warn(
        &doctor_catalog::GLOBAL_SHIM_TARGETS_STALE,
        &format!(
            "{} shim{} with wrong target ({}{}). Fix hint: \
             re-run `lpm install -g <pkg>` to reclaim the shim, or inspect \
             `~/.lpm/bin/<name>` if the mismatch is unexpected.",
            mismatches.len(),
            if mismatches.len() == 1 { "" } else { "s" },
            preview.join("; "),
            more,
        ),
    )
}

fn check_install_root_consistency(
    root: &lpm_common::LpmRoot,
    manifest: &lpm_global::GlobalManifest,
) -> Check {
    if manifest.packages.is_empty() {
        return Check::pass(
            &doctor_catalog::GLOBAL_INSTALL_ROOTS_EMPTY,
            "no packages to check",
        );
    }
    // Use `validate_install_root`, the authoritative predicate the
    // install pipeline and recovery both rely on. Marker presence alone
    // is weaker than the recovery contract: a half-corrupted install
    // can still have `.lpm-install-ready` while declared bin targets or
    // the lockfile are missing.
    //
    // `validate_install_root(install_root, Some(&entry.commands))`
    // covers:
    //   - root dir exists
    //   - `.lpm-install-ready` marker present + parseable
    //   - every command in `entry.commands` is in the marker's list
    //     AND has an executable bin target inside the root
    //   - `lpm.lock` is present + parseable
    //
    // Any deviation collapses into one bucket in the doctor report
    // — detailed diagnosis lives in `lpm install -g <pkg>`'s error
    // path, not in doctor's one-line-per-check surface.
    use lpm_global::InstallRootStatus;
    let mut missing: Vec<String> = Vec::new();
    let mut not_ready: Vec<(String, String)> = Vec::new();
    let mut registry_roots = 0usize;
    let mut local_link_roots = 0usize;
    for (name, entry) in &manifest.packages {
        let install_root = root.global_root().join(&entry.root);
        if entry.source == lpm_global::PackageSource::LocalLink {
            local_link_roots += 1;
            if !install_root.is_dir() {
                missing.push(name.clone());
                continue;
            }
            let install_bin = install_root.join("node_modules").join(".bin");
            let missing_shims: Vec<String> = entry
                .commands
                .iter()
                .filter(|command| !lpm_global::artifacts_complete(&install_bin, command))
                .cloned()
                .collect();
            if !missing_shims.is_empty() {
                not_ready.push((
                    name.clone(),
                    format!("LocalLinkMissingShims({})", missing_shims.join(", ")),
                ));
            }
            continue;
        }

        registry_roots += 1;
        let status = match lpm_global::validate_install_root(&install_root, Some(&entry.commands)) {
            Ok(s) => s,
            Err(e) => {
                // I/O error reading the root (permissions, etc.) —
                // treat as not-ready with the error as reason.
                not_ready.push((name.clone(), format!("validate I/O error: {e}")));
                continue;
            }
        };
        match status {
            InstallRootStatus::Ready { .. } => {} // healthy
            InstallRootStatus::RootMissing => missing.push(name.clone()),
            other => not_ready.push((name.clone(), format!("{other:?}"))),
        }
    }
    missing.sort();
    not_ready.sort_by(|a, b| a.0.cmp(&b.0));

    if missing.is_empty() && not_ready.is_empty() {
        return Check::pass(
            &doctor_catalog::GLOBAL_INSTALL_ROOTS_HEALTHY,
            &format!(
                "{} registry install root{} and {} local-link root{} healthy",
                registry_roots,
                if registry_roots == 1 { "" } else { "s" },
                local_link_roots,
                if local_link_roots == 1 { "" } else { "s" },
            ),
        );
    }
    let mut issues: Vec<String> = Vec::new();
    if !missing.is_empty() {
        issues.push(format!("{} missing: {}", missing.len(), missing.join(", ")));
    }
    if !not_ready.is_empty() {
        // List a few specific reasons so the user sees WHICH check
        // (marker vs bin target vs lockfile) failed, not just
        // "not ready." Authoritative diagnosis still lives in the
        // install pipeline; doctor's job is to flag + name.
        let preview: Vec<String> = not_ready
            .iter()
            .take(5)
            .map(|(pkg, reason)| format!("{pkg} [{reason}]"))
            .collect();
        let more = if not_ready.len() > preview.len() {
            format!(", +{} more", not_ready.len() - preview.len())
        } else {
            String::new()
        };
        issues.push(format!(
            "{} not ready: {}{}",
            not_ready.len(),
            preview.join(", "),
            more,
        ));
    }
    Check::fail(
        &doctor_catalog::GLOBAL_INSTALL_ROOTS_UNHEALTHY,
        &format!(
            "{}. Fix hint: `lpm uninstall -g <pkg>` and re-install to rebuild the install root.",
            issues.join("; "),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor_catalog::Severity;

    // ─── global-installs health checks ─────────────────

    use chrono::Utc;
    use lpm_common::LpmRoot;
    use lpm_global::{
        GlobalManifest, InstallReadyMarker, PackageEntry, PackageSource, write_marker,
    };

    fn pkg_entry(rel_root: &str) -> PackageEntry {
        PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-z".into(),
            source: PackageSource::UpstreamNpm,
            installed_at: Utc::now(),
            root: rel_root.into(),
            commands: vec!["bin-a".into()],
        }
    }

    #[test]
    fn check_global_manifest_validity_passes_when_manifest_reads_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("eslint".into(), pkg_entry("installs/eslint@9.24.0"));
        lpm_global::write_for(&root, &manifest).unwrap();

        let check = check_global_manifest_validity(&root);
        assert!(matches!(check.severity, Severity::Pass));
        assert!(check.detail.contains("1 package"));
    }

    #[test]
    fn check_global_manifest_validity_passes_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let check = check_global_manifest_validity(&root);
        assert!(matches!(check.severity, Severity::Pass));
        assert!(check.detail.contains("not present"));
    }

    #[test]
    fn check_global_manifest_validity_fails_when_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        std::fs::create_dir_all(root.global_root()).unwrap();
        std::fs::write(root.global_manifest(), b"not = valid = toml ; ;").unwrap();
        let check = check_global_manifest_validity(&root);
        assert!(matches!(check.severity, Severity::Fail));
        assert!(
            check.detail.contains("Fix hint"),
            "fail check must include a fix hint: {}",
            check.detail
        );
    }

    #[test]
    fn check_bin_dir_on_path_passes_when_bin_dir_in_path_env() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin = root.bin_dir().display().to_string();
        let _env = crate::test_env::ScopedEnv::set([("PATH", bin.into())]);
        let check = check_bin_dir_on_path(&root);
        assert!(matches!(check.severity, Severity::Pass));
    }

    #[test]
    fn check_bin_dir_on_path_warns_when_bin_dir_missing_from_path() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let _env = crate::test_env::ScopedEnv::set([("PATH", "/usr/bin:/bin".into())]);
        let check = check_bin_dir_on_path(&root);
        assert!(matches!(check.severity, Severity::Warn));
        assert!(check.detail.contains("Fix hint"));
    }

    #[test]
    fn check_orphaned_bin_shims_passes_when_bin_dir_contains_only_owned_names() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin_dir = root.bin_dir();
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("bin-a"), b"").unwrap();

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), pkg_entry("installs/pkg@1.0.0"));
        let check = check_orphaned_bin_shims(&root, &manifest);
        assert!(matches!(check.severity, Severity::Pass));
    }

    #[test]
    fn check_orphaned_bin_shims_warns_when_extra_files_present() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin_dir = root.bin_dir();
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::write(bin_dir.join("bin-a"), b"").unwrap();
        std::fs::write(bin_dir.join("leftover-ghost"), b"").unwrap();

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), pkg_entry("installs/pkg@1.0.0"));
        let check = check_orphaned_bin_shims(&root, &manifest);
        assert!(matches!(check.severity, Severity::Warn));
        assert!(check.detail.contains("leftover-ghost"));
        assert!(check.detail.contains("Fix hint"));
    }

    /// The shim-target verifier passes when every owned shim points at
    /// the expected `<install-root>/node_modules/.bin/<bin>`.
    #[cfg(unix)]
    #[test]
    fn check_global_shim_targets_passes_when_symlinks_point_at_expected_install_bin() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin_dir = root.bin_dir();
        std::fs::create_dir_all(&bin_dir).unwrap();

        let install_root = root.global_root().join("installs/pkg@1.0.0");
        let install_bin = install_root.join("node_modules").join(".bin");
        std::fs::create_dir_all(&install_bin).unwrap();
        std::fs::write(install_bin.join("bin-a"), b"").unwrap();

        std::os::unix::fs::symlink(install_bin.join("bin-a"), bin_dir.join("bin-a")).unwrap();

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), pkg_entry("installs/pkg@1.0.0"));
        let check = check_global_shim_targets(&root, &manifest);
        assert!(matches!(check.severity, Severity::Pass), "{}", check.detail);
        assert!(check.detail.contains("1 owned shim verified"));
    }

    /// A regular file at the shim path is a same-user PATH-hijack shape
    /// and must surface as a warning, not pass.
    #[cfg(unix)]
    #[test]
    fn check_global_shim_targets_warns_when_shim_is_regular_file_not_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin_dir = root.bin_dir();
        std::fs::create_dir_all(&bin_dir).unwrap();
        // A regular file at the shim path instead of a symlink — the
        // PATH-hijack shape.
        std::fs::write(bin_dir.join("bin-a"), b"#!/bin/sh\necho hijacked").unwrap();

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), pkg_entry("installs/pkg@1.0.0"));
        let check = check_global_shim_targets(&root, &manifest);
        assert!(matches!(check.severity, Severity::Warn));
        assert!(
            check.detail.contains("regular file at shim path"),
            "warn must name the regular-file vs symlink shape, got: {}",
            check.detail
        );
        assert!(check.detail.contains("PATH hijack"));
    }

    /// A symlink whose target points at the wrong install root must
    /// surface as a warning naming both the expected and actual target.
    #[cfg(unix)]
    #[test]
    fn check_global_shim_targets_warns_when_symlink_points_at_unexpected_target() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let bin_dir = root.bin_dir();
        std::fs::create_dir_all(&bin_dir).unwrap();
        // Symlink to a totally unrelated path — the stale/hijack shape.
        std::os::unix::fs::symlink("/tmp/somewhere-else", bin_dir.join("bin-a")).unwrap();

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), pkg_entry("installs/pkg@1.0.0"));
        let check = check_global_shim_targets(&root, &manifest);
        assert!(matches!(check.severity, Severity::Warn));
        assert!(
            check.detail.contains("points at /tmp/somewhere-else"),
            "warn must name the actual target, got: {}",
            check.detail
        );
    }

    /// A TOML-valid manifest with structurally invalid rows must fail
    /// with the structural-invalid catalog entry, not pass.
    #[test]
    fn check_global_manifest_validity_fails_when_package_root_is_structurally_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        std::fs::create_dir_all(root.global_root()).unwrap();
        let mut manifest = GlobalManifest::default();
        manifest.packages.insert(
            "evilpkg".into(),
            PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                // Poisoned shape — `..` traversal must be refused.
                root: "../escape".into(),
                commands: vec!["bin-a".into()],
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let check = check_global_manifest_validity(&root);
        assert!(matches!(check.severity, Severity::Fail), "{}", check.detail);
        assert!(check.detail.contains("structurally invalid"));
        assert!(check.detail.contains("../escape"));
    }

    /// A dangling alias row must also fail the structural check.
    #[test]
    fn check_global_manifest_validity_fails_on_dangling_alias_row() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        std::fs::create_dir_all(root.global_root()).unwrap();
        let mut manifest = GlobalManifest::default();
        manifest.aliases.insert(
            "ghost-alias".into(),
            lpm_global::AliasEntry {
                package: "missing-pkg".into(),
                bin: "anything".into(),
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();

        let check = check_global_manifest_validity(&root);
        assert!(matches!(check.severity, Severity::Fail), "{}", check.detail);
        assert!(check.detail.contains("ghost-alias"));
        assert!(check.detail.contains("missing-pkg"));
        assert!(check.detail.contains("dangling alias row"));
    }

    /// Missing trusted-deps state passes with a "no host-global approvals"
    /// note. Other failure modes are covered by additional tests below.
    #[test]
    fn check_global_trusted_deps_passes_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let check = check_global_trusted_deps(&root);
        assert!(matches!(check.severity, Severity::Pass));
        assert!(check.detail.contains("not present"));
    }

    /// Malformed trusted-deps JSON fails with the schema-reset
    /// remediation hint.
    #[test]
    fn check_global_trusted_deps_fails_when_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let path = root.global_trusted_deps();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{not valid json").unwrap();
        let check = check_global_trusted_deps(&root);
        assert!(matches!(check.severity, Severity::Fail));
        assert!(check.detail.contains("Fix hint"));
    }

    /// Build a complete install root that passes `validate_install_root`:
    /// marker + executable bin target for every command + parseable
    /// `lpm.lock`. Mirrors the `make_complete_root` helper in
    /// `lpm-global::install_root` tests, scoped here for doctor tests.
    fn make_ready_install_root(install_root: &std::path::Path, commands: &[&str]) {
        let bin = install_root.join("node_modules").join(".bin");
        std::fs::create_dir_all(&bin).unwrap();
        for cmd in commands {
            let target = bin.join(cmd);
            std::fs::write(&target, b"#!/bin/sh\necho ok\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        std::fs::write(
            install_root.join("lpm.lock"),
            lpm_global::MINIMAL_VALID_LOCKFILE_TOML,
        )
        .unwrap();
        write_marker(
            install_root,
            &InstallReadyMarker::new(commands.iter().map(|s| (*s).to_string()).collect()),
        )
        .unwrap();
    }

    #[test]
    fn check_install_root_consistency_passes_when_all_roots_are_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.global_root().join("installs/pkg@1.0.0");
        make_ready_install_root(&install_root, &["bin-a"]);

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("pkg".into(), pkg_entry("installs/pkg@1.0.0"));
        let check = check_install_root_consistency(&root, &manifest);
        assert!(
            matches!(check.severity, Severity::Pass),
            "ready root must pass: {}",
            check.detail
        );
    }

    /// A marker with a missing bin target is not a ready install root.
    /// Doctor must rely on `validate_install_root`, not marker presence.
    #[test]
    fn check_install_root_consistency_fails_when_bin_target_missing_under_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.global_root().join("installs/corrupt@1.0.0");
        make_ready_install_root(&install_root, &["bin-a"]);
        // Now corrupt the install: delete the bin target. Marker still
        // claims bin-a is there.
        let bin_target = install_root.join("node_modules").join(".bin").join("bin-a");
        std::fs::remove_file(&bin_target).unwrap();
        assert!(!bin_target.exists());

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("corrupt".into(), pkg_entry("installs/corrupt@1.0.0"));
        let check = check_install_root_consistency(&root, &manifest);
        assert!(
            matches!(check.severity, Severity::Fail),
            "marker-present-but-bin-target-missing must Fail: {}",
            check.detail,
        );
        assert!(check.detail.contains("not ready"));
        assert!(check.detail.contains("corrupt"));
    }

    /// Companion: lockfile corruption under a present marker must also
    /// be Fail. Covers the third leg of `validate_install_root`'s
    /// triple-check.
    #[test]
    fn check_install_root_consistency_fails_when_lockfile_missing_under_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.global_root().join("installs/nolock@1.0.0");
        make_ready_install_root(&install_root, &["bin-a"]);
        std::fs::remove_file(install_root.join("lpm.lock")).unwrap();

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("nolock".into(), pkg_entry("installs/nolock@1.0.0"));
        let check = check_install_root_consistency(&root, &manifest);
        assert!(matches!(check.severity, Severity::Fail));
    }

    #[test]
    fn check_install_root_consistency_fails_when_root_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let mut manifest = GlobalManifest::default();
        // Manifest claims the install but the dir doesn't exist.
        manifest
            .packages
            .insert("ghost".into(), pkg_entry("installs/ghost@1.0.0"));
        let check = check_install_root_consistency(&root, &manifest);
        assert!(matches!(check.severity, Severity::Fail));
        assert!(check.detail.contains("missing"));
        assert!(check.detail.contains("ghost"));
        assert!(check.detail.contains("Fix hint"));
    }

    #[test]
    fn check_install_root_consistency_fails_when_marker_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let install_root = root.global_root().join("installs/unready@1.0.0");
        std::fs::create_dir_all(&install_root).unwrap();
        // Intentionally NO marker. `validate_install_root` returns
        // `MissingMarker` which the new Check 17 renders as "not ready".

        let mut manifest = GlobalManifest::default();
        manifest
            .packages
            .insert("unready".into(), pkg_entry("installs/unready@1.0.0"));
        let check = check_install_root_consistency(&root, &manifest);
        assert!(matches!(check.severity, Severity::Fail));
        assert!(
            check.detail.contains("not ready"),
            "doctor uses the authoritative predicate and renders all \
             sub-failures under the `not ready` category: {}",
            check.detail,
        );
        assert!(check.detail.contains("MissingMarker"));
    }
}
