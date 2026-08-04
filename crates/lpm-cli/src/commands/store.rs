use crate::install_ui;
use lpm_common::color::Painted;
use lpm_common::{
    LpmError, LpmRoot, format_bytes, sanitize_for_terminal, with_exclusive_lock, with_shared_lock,
};
use lpm_store::PackageStore;
use std::collections::{HashMap, HashSet};

/// Manage the global content-addressable package store.
///
/// Actions: verify, path, clean.
///
/// Locking model:
/// - `verify` traverses the store and acquires the **shared** half of
///   the store lock so it can't race a concurrent `clean` mid-walk.
/// - `clean` is destructive and acquires the **exclusive** half — it
///   waits for in-flight readers (installs, patch, rebuild,
///   approve-scripts, audit, store verify, cache prune) to release
///   before touching the CAS.
/// - `path` just prints the configured store root (no I/O); no lock needed.
///
/// Reachability-aware orphan cleanup lives in `lpm cache prune` —
/// `lpm store` covers integrity, listing the path, and the blunt wipe.
pub async fn run(action: &str, deep: bool, fix: bool, json_output: bool) -> Result<(), LpmError> {
    let store = PackageStore::default_location()?;
    let root = LpmRoot::from_env()?;

    match action {
        "verify" => with_shared_lock(root.store_lock(), || {
            run_verify(&root, &store, deep, fix, json_output)
        }),
        "path" => {
            let path = store.root().display().to_string();
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"success": true, "path": path})
                    )
                    .unwrap()
                );
            } else {
                println!("{}", lpm_common::sanitize_terminal_inline(&path));
            }
            Ok(())
        }
        "clean" => with_exclusive_lock(root.store_lock(), || run_clean(&root, json_output)),
        _ => Err(LpmError::Store(format!(
            "unknown store action: {action}. Available: verify, path, clean. \
             For reachability-aware orphan cleanup, use `lpm cache prune`."
        ))),
    }
}

/// Blunt store wipe — removes the v1, v2, and v3 store directories in their
/// entirety.
///
/// This preserves the old whole-store wipe behavior as an explicit,
/// scoped, named command for the rare "nuke
/// everything" workflow. For everyday maintenance use
/// `lpm cache prune --apply`, which is reference-aware and won't evict packages
/// currently referenced by a project lockfile.
///
///
/// The human and JSON output cover all supported store versions so "Wiped
/// package store" remains truthful across default and rollback layouts.
///
/// The version subdirectories are the unit of removal so the
/// outer `store/` dir (`.gc.lock`, other control files) stays intact.
fn run_clean(root: &LpmRoot, json_output: bool) -> Result<(), LpmError> {
    let v1 = root.store_v1();
    let v2 = root.store_root().join("v2");
    let v3 = root.store_root().join("v3");

    let v1_existed = v1.exists();
    let v2_existed = v2.exists();
    let v3_existed = v3.exists();

    if !v1_existed && !v2_existed && !v3_existed {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&clean_json_payload(&v1, &v2, &v3, 0, 0, 0)).unwrap()
            );
        } else {
            install_ui::done("Store is already empty");
        }
        return Ok(());
    }

    let v1_bytes = if v1_existed {
        crate::commands::cache::dir_size(&v1).unwrap_or(0)
    } else {
        0
    };
    let v2_bytes = if v2_existed {
        crate::commands::cache::dir_size(&v2).unwrap_or(0)
    } else {
        0
    };
    let v3_bytes = if v3_existed {
        crate::commands::cache::dir_size(&v3).unwrap_or(0)
    } else {
        0
    };

    if v1_existed {
        std::fs::remove_dir_all(&v1)?;
    }
    if v2_existed {
        std::fs::remove_dir_all(&v2)?;
    }
    if v3_existed {
        std::fs::remove_dir_all(&v3)?;
    }

    let bytes_before = v1_bytes + v2_bytes + v3_bytes;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&clean_json_payload(
                &v1, &v2, &v3, v1_bytes, v2_bytes, v3_bytes,
            ))
            .unwrap()
        );
    } else {
        install_ui::done_untrusted(&format!(
            "Wiped package store · freed {}",
            format_bytes(bytes_before)
        ));
        eprintln!(
            "  {}",
            install_ui::dim("Use `lpm install` to repopulate from lockfiles.")
        );
    }

    Ok(())
}

fn clean_json_payload(
    v1: &std::path::Path,
    v2: &std::path::Path,
    v3: &std::path::Path,
    v1_removed_bytes: u64,
    v2_removed_bytes: u64,
    v3_removed_bytes: u64,
) -> serde_json::Value {
    let removed_bytes = v1_removed_bytes + v2_removed_bytes + v3_removed_bytes;
    serde_json::json!({
        "success": true,
        "removed_bytes": removed_bytes,
        "removed": format_bytes(removed_bytes),
        // Legacy alias retained for clients that previously read the
        // v1-only clean response. `v1_path` / `v2_path` are the
        // authoritative fields post-v2.
        "path": v1.display().to_string(),
        "v1_path": v1.display().to_string(),
        "v2_path": v2.display().to_string(),
        "v3_path": v3.display().to_string(),
        "v1_removed_bytes": v1_removed_bytes,
        "v2_removed_bytes": v2_removed_bytes,
        "v3_removed_bytes": v3_removed_bytes,
    })
}

/// One walked store entry — v1 or v2 — handed to the unified verify
/// loop. `inline_integrity` is `Some` on v2 (read from the link
/// sidecar's `source_sri`) and `None` on v1 (the loop falls back to
/// `read_stored_integrity` against `<dir>/.integrity`).
struct StoreVerifyEntry {
    name: String,
    version: String,
    dir: std::path::PathBuf,
    inline_integrity: Option<String>,
    object_path: Option<String>,
    store_version: Option<lpm_store::StoreVersion>,
    tree_digest: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct StoreVerifyCounts {
    links: usize,
    objects: usize,
    sources: usize,
    trees: usize,
    blobs: usize,
    materialized: usize,
}

impl StoreVerifyCounts {
    fn is_empty(self) -> bool {
        self.links == 0
            && self.objects == 0
            && self.sources == 0
            && self.trees == 0
            && self.blobs == 0
            && self.materialized == 0
    }
}

/// Verify presence and lockfile-marker consistency of every store
/// entry.
///
/// Basic mode: each package directory must exist and contain a
/// non-empty `package.json`. Catches missing-directory, empty-
/// directory, and missing-manifest corruption.
///
/// Deep mode (`--deep`): additionally parses `package.json` to assert
/// the declared `name`/`version` match the store-entry coordinates,
/// and compares the stored integrity marker (`v1` `.integrity` file or
/// virtual-store link sidecar's `source_sri`) against the current project
/// lockfile's claimed integrity for that package. Detects marker
/// drift and lockfile poisoning that would change the claimed source
/// hash.
///
/// Deep mode also re-hashes every v3 CAS blob and validates its content-plus-
/// mode key. Legacy v1/v2 extracted directories retain marker-consistency
/// verification because they do not have file-level CAS identities.
///
/// Fix mode (`--fix`): auto-repair stale `.lpm-security.json`
/// behavioral caches. Without `--fix`, verify is read-only.
///
/// Walks v1 package directories plus v2 and v3 virtual-store entries.
fn run_verify(
    lpm_root: &LpmRoot,
    store: &PackageStore,
    deep: bool,
    fix: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let deep = deep || fix;
    let mut packages: Vec<StoreVerifyEntry> = list_v1_verify_entries(store)?;
    let (v2_entries, mut sidecar_issues) = list_v2_verify_entries(lpm_root)?;
    let (v3_entries, mut v3_sidecar_issues) =
        list_virtual_verify_entries(lpm_root, lpm_store::StoreVersion::V3)?;
    let virtual_link_count =
        v2_entries.len() + sidecar_issues.len() + v3_entries.len() + v3_sidecar_issues.len();
    packages.extend(v2_entries);
    packages.extend(v3_entries);
    sidecar_issues.append(&mut v3_sidecar_issues);
    let mut virtual_object_paths =
        list_virtual_object_paths(lpm_root, lpm_store::StoreVersion::V2)?;
    virtual_object_paths.extend(list_virtual_object_paths(
        lpm_root,
        lpm_store::StoreVersion::V3,
    )?);
    let v3_store =
        lpm_store::v2::Store::from_lpm_root_for_version(lpm_root, lpm_store::StoreVersion::V3);
    let cas_verification = v3_store.verify_file_cas(deep)?.unwrap_or_default();
    sidecar_issues.extend(
        cas_verification
            .issues
            .iter()
            .map(|issue| format!("v3 CAS — {}", sanitize_for_terminal(issue))),
    );
    let verify_counts = StoreVerifyCounts {
        links: virtual_link_count,
        objects: virtual_object_paths.len(),
        sources: cas_verification.sources,
        trees: cas_verification.trees,
        blobs: cas_verification.blobs,
        materialized: cas_verification.materialized,
    };

    if !json_output {
        install_ui::phase("Verifying store integrity");
        print_verify_counts(verify_counts);
    }

    let (lockfile_integrity, lockfile_issue) = load_lockfile_integrity_for_verify(deep);
    let mut corrupted: Vec<String> =
        Vec::with_capacity(sidecar_issues.len() + usize::from(lockfile_issue.is_some()));
    if let Some(issue) = lockfile_issue {
        corrupted.push(issue);
    }
    corrupted.append(&mut sidecar_issues);

    if packages.is_empty() && corrupted.is_empty() && verify_counts.is_empty() {
        if json_output {
            let mut result = build_verify_envelope(true, deep, 0, 0, 0, &[], 0, 0);
            attach_cas_verification(&mut result, &cas_verification, deep);
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        } else {
            install_ui::done("Store is empty — nothing to verify");
        }
        return Ok(());
    }

    let mut verified = 0u32;
    let mut security_mismatches = 0u32;
    let mut security_reanalyzed = 0u32;
    let mut security_fix_failures = 0u32;
    let mut referenced_objects_ok = true;
    let v2_paths = lpm_store::v2::StoreV2Paths::from_lpm_root(lpm_root);

    for entry in &packages {
        let StoreVerifyEntry {
            name,
            version,
            dir,
            inline_integrity,
            object_path,
            store_version,
            tree_digest,
        } = entry;
        // L59: every state-derived field that may carry sidecar / dir
        // / package.json control bytes goes through sanitize_for_terminal
        // before format!. Without this a tampered sidecar can ride
        // ESC/BEL/OSC sequences into the human emitter.
        let safe_name = sanitize_for_terminal(name);
        let safe_version = sanitize_for_terminal(version);

        if let Some(object_path) = object_path {
            let safe_object_path = sanitize_for_terminal(object_path);
            let Some(source_sri) = inline_integrity.as_deref() else {
                referenced_objects_ok = false;
                corrupted.push(format!(
                    "{safe_name}@{safe_version} — virtual-store link missing source integrity for {safe_object_path}"
                ));
                continue;
            };
            let paths = if *store_version == Some(lpm_store::StoreVersion::V3) {
                lpm_store::v2::StoreV2Paths::from_lpm_root_v3(lpm_root)
            } else {
                v2_paths.clone()
            };
            let expected_object_path = match paths.relative_object_path(source_sri) {
                Ok(path) => path,
                Err(e) => {
                    referenced_objects_ok = false;
                    corrupted.push(format!(
                        "{safe_name}@{safe_version} — invalid referenced object hash: {}",
                        sanitize_for_terminal(&e.to_string())
                    ));
                    continue;
                }
            };
            if *object_path != expected_object_path {
                referenced_objects_ok = false;
                corrupted.push(format!(
                    "{safe_name}@{safe_version} — object path mismatch: sidecar '{}' != hash '{}'",
                    safe_object_path,
                    sanitize_for_terminal(&expected_object_path)
                ));
                continue;
            }
            if !virtual_object_paths.contains(&(
                store_version.unwrap_or(lpm_store::StoreVersion::V2),
                object_path.clone(),
            )) {
                referenced_objects_ok = false;
                corrupted.push(format!(
                    "{safe_name}@{safe_version} — referenced object missing: {safe_object_path}"
                ));
                continue;
            }
            let expected_tree_digest = if *store_version == Some(lpm_store::StoreVersion::V3) {
                match v3_store.file_cas_tree_digest(source_sri) {
                    Ok(digest) => digest,
                    Err(error) => {
                        corrupted.push(format!(
                            "{safe_name}@{safe_version} — invalid CAS source record: {}",
                            sanitize_for_terminal(&error.to_string())
                        ));
                        continue;
                    }
                }
            } else {
                None
            };
            if tree_digest.as_deref() != expected_tree_digest.as_deref() {
                corrupted.push(format!(
                    "{safe_name}@{safe_version} — CAS tree reference mismatch"
                ));
                continue;
            }
        }

        // Check 1: directory exists
        if !dir.exists() {
            corrupted.push(format!("{safe_name}@{safe_version} — directory missing"));
            continue;
        }

        // Check 2: package.json exists
        let pkg_json_path = dir.join("package.json");
        if !pkg_json_path.exists() {
            corrupted.push(format!("{safe_name}@{safe_version} — missing package.json"));
            continue;
        }

        // Check 3: directory is non-empty (has at least package.json + something else,
        // or at minimum package.json itself)
        let file_count = match std::fs::read_dir(dir) {
            Ok(entries) => entries.count(),
            Err(e) => {
                corrupted.push(format!(
                    "{safe_name}@{safe_version} — unreadable directory: {}",
                    sanitize_for_terminal(&e.to_string())
                ));
                continue;
            }
        };

        if file_count == 0 {
            corrupted.push(format!("{safe_name}@{safe_version} — empty directory"));
            continue;
        }

        // Deep mode: parse package.json, validate name/version fields,
        // and verify integrity hash against lockfile.
        if deep {
            match lpm_common::read_text_file_capped(
                &pkg_json_path,
                lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
            ) {
                Ok(content) => {
                    match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(pkg) => {
                            // Validate name matches
                            if let Some(declared_name) = pkg.get("name").and_then(|v| v.as_str())
                                && declared_name != name
                            {
                                corrupted.push(format!(
                                    "{safe_name}@{safe_version} — package.json name mismatch: declared '{}'",
                                    sanitize_for_terminal(declared_name)
                                ));
                                continue;
                            }
                            // Validate version matches
                            if let Some(declared_version) =
                                pkg.get("version").and_then(|v| v.as_str())
                                && declared_version != version
                            {
                                corrupted.push(format!(
                                    "{safe_name}@{safe_version} — package.json version mismatch: declared '{}'",
                                    sanitize_for_terminal(declared_version)
                                ));
                                continue;
                            }
                        }
                        Err(e) => {
                            corrupted.push(format!(
                                "{safe_name}@{safe_version} — invalid package.json: {}",
                                sanitize_for_terminal(&e.to_string())
                            ));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    corrupted.push(format!(
                        "{safe_name}@{safe_version} — unreadable package.json: {}",
                        sanitize_for_terminal(&e.to_string())
                    ));
                    continue;
                }
            }

            // Verify integrity hash: compare stored integrity with lockfile.
            // V2 entries carry `inline_integrity` (the link sidecar's
            // `source_sri`); V1 entries fall back to
            // `read_stored_integrity` (`.integrity` sentinel file).
            let key = format!("{name}@{version}");
            if let Some(expected_integrity) = lockfile_integrity.get(&key) {
                let stored = inline_integrity
                    .clone()
                    .or_else(|| lpm_store::read_stored_integrity(dir));
                match stored {
                    Some(stored) => {
                        if stored != *expected_integrity {
                            corrupted.push(format!(
                                "{safe_name}@{safe_version} — integrity mismatch: stored '{}...' != lockfile '{}...'",
                                truncate_chars_safe(&sanitize_for_terminal(&stored), 20),
                                truncate_chars_safe(&sanitize_for_terminal(expected_integrity), 20),
                            ));
                            continue;
                        }
                    }
                    None => {
                        // No `.integrity` file AND no v2 sidecar
                        // integrity — package was stored before
                        // integrity tracking. Not an error, but noted
                        // at debug level.
                        tracing::debug!(
                            "{name}@{version}: no integrity record (pre-integrity store)"
                        );
                    }
                }
            }

            // Security cross-check: re-run behavioral analysis and compare with cached.
            // Read-only by default — only writes when --fix is passed.
            let cached = lpm_security::behavioral::read_cached_analysis(dir);
            let fresh = lpm_security::behavioral::analyze_package(dir);

            match cached {
                Some(ref cached_analysis) => {
                    if !security_analysis_matches(cached_analysis, &fresh) {
                        security_mismatches += 1;
                        if fix {
                            let fixed = match write_security_cache_for_verify(
                                dir,
                                &fresh,
                                &safe_name,
                                &safe_version,
                            ) {
                                Ok(()) => {
                                    security_reanalyzed += 1;
                                    true
                                }
                                Err(issue) => {
                                    security_fix_failures += 1;
                                    tracing::warn!("{issue}");
                                    corrupted.push(issue);
                                    false
                                }
                            };
                            if !json_output {
                                let status = if fixed { "fixed" } else { "fix failed" };
                                install_ui::warn_untrusted(&format!(
                                    "{safe_name}@{safe_version} — security analysis mismatch ({status})"
                                ));
                            }
                        } else if !json_output {
                            install_ui::warn_untrusted(&format!(
                                "{name}@{version} — security analysis mismatch (use --fix to refresh)"
                            ));
                        }
                    }
                }
                None => {
                    security_mismatches += 1;
                    if fix {
                        let fixed = match write_security_cache_for_verify(
                            dir,
                            &fresh,
                            &safe_name,
                            &safe_version,
                        ) {
                            Ok(()) => {
                                security_reanalyzed += 1;
                                true
                            }
                            Err(issue) => {
                                security_fix_failures += 1;
                                tracing::warn!("{issue}");
                                corrupted.push(issue);
                                false
                            }
                        };
                        if !json_output {
                            let status = if fixed { "fixed" } else { "fix failed" };
                            install_ui::warn_untrusted(&format!(
                                "{safe_name}@{safe_version} — missing security cache ({status})"
                            ));
                        }
                    } else if !json_output {
                        install_ui::warn_untrusted(&format!(
                            "{name}@{version} — missing security cache (use --fix to generate)"
                        ));
                    }
                }
            }
        }

        verified += 1;
    }

    // Distinguish
    // "store entries" (one per v1 dir + one per v2 link entry) from
    // "unique packages" (deduped on `(name, version)`). During v1↔v2
    // migration AND under multi-source-same-coords + cross-project
    // graph-key splits, the same `(name, version)` legitimately appears
    // multiple times in the merged input list — each entry is
    // independently verifiable bytes-on-disk and the count stays
    // truthful. Pre-fix the human-output line said "N packages
    // verified", which suggested unique-package inventory; the count
    // was inflated relative to that mental model and confused users
    // looking at an in-flight migration.
    //
    // Fix: present the entry count under the term "store entries" and
    // surface a secondary `unique_coords` count for both human and
    // JSON output. Optional duplication breakdown when the two
    // diverge.
    let (unique_coords, duplicated_count) = compute_verify_dedup_counts(&packages);

    // L56: `success` must reflect whether the store is healthy.
    // Pre-fix this was hard-coded to `true` and the process exit was
    // always 0, so a CI gate built on `lpm store verify --json` would
    // pass through corrupted entries. The exit signal tracks corruption
    // (missing/empty directories, missing package.json, name/version
    // mismatches, invalid package.json, integrity mismatches, malformed
    // v2 sidecars per L57). Security-analysis mismatches remain advisory
    // — they're a per-package cache refresh hint, not a corrupted-bytes
    // signal, and the human/JSON output already names them with a
    // `--fix` remediation pointer.
    let success = corrupted.is_empty();

    if json_output {
        let mut result = build_verify_envelope(
            success,
            deep,
            verified,
            unique_coords,
            duplicated_count,
            &corrupted,
            security_mismatches,
            security_reanalyzed,
        );
        attach_cas_verification(&mut result, &cas_verification, deep);
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else if corrupted.is_empty() {
        if referenced_objects_ok {
            install_ui::done("Checked every referenced object hash");
        }
        // F4: noun is "store entries" (truthful for v1+v2 merged
        // walks); secondary `(N unique packages)` parenthetical when
        // the two counts differ — almost always during a store-version
        // migration or after a multi-source-same-coords install.
        let mut msg = if duplicated_count > 0 {
            format!(
                "{verified} store entries verified ({unique_coords} unique packages, {duplicated_count} duplicated across store versions / graph keys), all OK"
            )
        } else {
            format!("{verified} store entries verified, all OK")
        };
        if deep && security_reanalyzed > 0 {
            msg.push_str(&format!(
                " ({security_reanalyzed} security cache{} refreshed)",
                if security_reanalyzed == 1 { "" } else { "s" }
            ));
        }
        if deep && security_mismatches > 0 && !fix {
            install_ui::warn_untrusted(&format!(
                "{verified} store entries verified, {security_mismatches} security analysis mismatch{} (use --fix to refresh)",
                if security_mismatches == 1 { "" } else { "es" }
            ));
        } else if deep && security_mismatches > 0 && fix {
            install_ui::warn_untrusted(&format!(
                "{verified} store entries verified, {security_mismatches} security analysis mismatch{} (fixed)",
                if security_mismatches == 1 { "" } else { "es" }
            ));
        } else {
            install_ui::done_untrusted(&format!("Store verified · {msg}"));
        }
        if deep {
            // Make the scope explicit so users don't assume a clean
            // exit attests to bytes-on-disk integrity.
            eprintln!(
                "  {}",
                install_ui::dim(
                    "Note: --deep re-hashes v3 CAS blobs; legacy v1/v2 extracted directories retain marker-consistency verification."
                )
            );
        }
    } else {
        install_ui::failed_untrusted(&format!("{} corrupted, {} OK", corrupted.len(), verified));
        for issue in &corrupted {
            install_ui::warn_untrusted(issue);
        }
        if deep && security_mismatches > 0 {
            let suffix = if fix && security_fix_failures > 0 {
                "fix failed"
            } else if fix {
                "fixed"
            } else {
                "use --fix to refresh"
            };
            install_ui::warn_untrusted(&format!(
                "{security_mismatches} security analysis mismatch{} ({suffix})",
                if security_mismatches == 1 { "" } else { "es" }
            ));
        }
        eprintln!();
        eprintln!(
            "    Fix: {} && {}",
            "lpm cache prune --apply".bold(),
            "lpm install".bold()
        );
    }

    // L56: surface corruption to the process exit code so CI gates
    // built on `$?` see the failure too. JSON mode already wrote its
    // envelope to stdout (with `"success": false`); ExitCode is the
    // explicit "I've emitted my own output, just propagate status"
    // signal the top-level handler honours.
    if !success {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

fn print_verify_counts(counts: StoreVerifyCounts) {
    eprintln!(
        "  {} {} {} {} {} {} {} {} {} {} {} {}",
        install_ui::dim("links"),
        counts.links,
        install_ui::dim("/ objects"),
        counts.objects,
        install_ui::dim("/ sources"),
        counts.sources,
        install_ui::dim("/ trees"),
        counts.trees,
        install_ui::dim("/ blobs"),
        counts.blobs,
        install_ui::dim("/ materialized"),
        counts.materialized,
    );
}

fn attach_cas_verification(
    result: &mut serde_json::Value,
    verification: &lpm_store::v3::FileCasVerification,
    deep: bool,
) {
    let blob_integrity_recomputed = deep && verification.blobs_rehashed > 0;
    let check_kind = if deep { "content_hash" } else { "metadata" };
    result["bytes_integrity_recomputed"] = serde_json::json!(blob_integrity_recomputed);
    result["cas"] = serde_json::json!({
        "check_kind": check_kind,
        "sources": verification.sources,
        "trees": verification.trees,
        "blobs": verification.blobs,
        "blobs_rehashed": verification.blobs_rehashed,
        "materialized": verification.materialized,
        "orphaned_sources": verification.orphaned_sources,
        "orphaned_trees": verification.orphaned_trees,
        "orphaned_blobs": verification.orphaned_blobs,
        "orphaned_materialized": verification.orphaned_materialized,
        "blob_integrity_recomputed": blob_integrity_recomputed,
    });
}

/// derive the
/// `(unique_coords, duplicated_count)` pair from the merged store-version
/// entry list. Pure compute over already-walked input, factored out
/// for unit testability.
///
/// `unique_coords` counts distinct `(name, version)` pairs across the
/// whole list. `duplicated_count` is `entries.len() - unique_coords`,
/// surfaced separately so the human-output line can describe what
/// drove the divergence (almost always entries split across versions during a
/// migration or entries split across graph keys via
/// multi-source-same-coords").
/// Truncate `s` to at most `max_chars` Unicode scalar values, using
/// `chars().take(...)` so the slice always lands on a char boundary.
/// L59: the pre-fix integrity-preview formatter did `&s[..s.len().min(20)]`,
/// which can panic on non-ASCII when the byte boundary lands inside a
/// multibyte character — a tampered sidecar with a unicode SRI prefix
/// would crash the diagnostic path.
fn truncate_chars_safe(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

fn compute_verify_dedup_counts(entries: &[StoreVerifyEntry]) -> (usize, usize) {
    let mut seen = std::collections::HashSet::with_capacity(entries.len());
    for entry in entries {
        seen.insert((entry.name.clone(), entry.version.clone()));
    }
    let unique = seen.len();
    let duplicated = entries.len().saturating_sub(unique);
    (unique, duplicated)
}

fn load_lockfile_integrity_for_verify(deep: bool) -> (HashMap<String, String>, Option<String>) {
    if !deep {
        return (HashMap::new(), None);
    }

    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => {
            return (
                HashMap::new(),
                Some(format!(
                    "lpm.lock — unreadable: {}",
                    sanitize_for_terminal(&e.to_string())
                )),
            );
        }
    };
    match lpm_lockfile::Lockfile::read_for_project(&cwd) {
        Ok(project) => {
            let integrity = project
                .lockfile
                .packages
                .iter()
                .filter_map(|package| {
                    package.integrity.as_ref().map(|integrity| {
                        (
                            format!("{}@{}", package.name, package.version),
                            integrity.clone(),
                        )
                    })
                })
                .collect();
            (integrity, None)
        }
        Err(lpm_lockfile::LockfileError::NotFound(_)) => (HashMap::new(), None),
        Err(e) => (
            HashMap::new(),
            Some(format!(
                "lpm.lock — unreadable: {}",
                sanitize_for_terminal(&e.to_string())
            )),
        ),
    }
}

/// Build the JSON envelope `lpm store verify --json` emits to stdout.
/// Pure compute over already-walked input, factored out so tests can
/// assert the contract directly without capturing stdout.
///
/// `legacy_check_kind` names basic presence vs. lockfile-marker consistency
/// for v1/v2 extracted entries. `check_kind` remains its compatibility alias.
/// [`attach_cas_verification`] records the distinct v3 CAS scope and flips
/// `bytes_integrity_recomputed` only when a deep pass actually re-hashed one
/// or more blobs.
#[allow(clippy::too_many_arguments)]
fn build_verify_envelope(
    success: bool,
    deep: bool,
    verified: u32,
    unique_coords: usize,
    duplicated_count: usize,
    corrupted: &[String],
    security_mismatches: u32,
    security_reanalyzed: u32,
) -> serde_json::Value {
    let check_kind = if deep {
        "lockfile_marker_consistency"
    } else {
        "presence"
    };
    let mut result = serde_json::json!({
        "success": success,
        "check_kind": check_kind,
        "legacy_check_kind": check_kind,
        "bytes_integrity_recomputed": false,
        // **F4** — `verified` was previously documented as "packages"
        // but counted store entries. Renamed to `entries_verified` to
        // match the actual semantic. `verified` retained as an alias
        // for one release window so JSON consumers (CI dashboards,
        // audit scripts) don't break overnight.
        "entries_verified": verified,
        "verified": verified,
        "unique_coords": unique_coords,
        "duplicated_entries": duplicated_count,
        "corrupted": corrupted.len(),
        "issues": corrupted,
    });
    if deep {
        result["securityMismatches"] = serde_json::json!(security_mismatches);
        result["securityReanalyzed"] = serde_json::json!(security_reanalyzed);
    }
    result
}

fn list_v1_verify_entries(store: &PackageStore) -> Result<Vec<StoreVerifyEntry>, LpmError> {
    let store_dir = store.root().join("v1");
    if !store_dir.exists() {
        return Ok(Vec::new());
    }

    let mut packages = Vec::new();
    for entry in std::fs::read_dir(&store_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let dir_name = entry.file_name().to_string_lossy().to_string();
        if dir_name.contains(".tmp.") {
            continue;
        }

        let Some(at_pos) = dir_name.rfind('@') else {
            continue;
        };

        let name = dir_name[..at_pos].replace('+', "/");
        let version = dir_name[at_pos + 1..].to_string();
        if name.is_empty() || version.is_empty() {
            continue;
        }

        let dir = store.package_dir(&name, &version);
        packages.push(StoreVerifyEntry {
            name,
            version,
            dir,
            inline_integrity: None,
            object_path: None,
            store_version: None,
            tree_digest: None,
        });
    }

    packages.sort_by(|a, b| (a.name.as_str(), a.version.as_str()).cmp(&(&b.name, &b.version)));
    Ok(packages)
}

/// enumerate v2 link entries
/// for `lpm store verify`. Each link's sidecar (`.lpm-link-meta.json`)
/// supplies `(name, version, source_sri)` directly; the materialized
/// package dir is `<link>/node_modules/<name>/`. Multi-source-same-coords
/// yields one entry per link, so two links sharing `(name, version)`
/// get verified independently.
///
/// Returns `(entries, sidecar_issues)`. `sidecar_issues` lists every
/// v2 link directory whose `.lpm-link-meta.json` was missing,
/// malformed, schema-mismatched, or carried an unsafe name (L57). The
/// caller folds these into the corruption list so verify reports the
/// problem instead of inheriting the iterator's skip-on-malformed
/// shape.
fn list_v2_verify_entries(
    lpm_root: &LpmRoot,
) -> Result<(Vec<StoreVerifyEntry>, Vec<String>), LpmError> {
    list_virtual_verify_entries(lpm_root, lpm_store::StoreVersion::V2)
}

fn list_virtual_verify_entries(
    lpm_root: &LpmRoot,
    store_version: lpm_store::StoreVersion,
) -> Result<(Vec<StoreVerifyEntry>, Vec<String>), LpmError> {
    let store_v2 = lpm_store::v2::Store::from_lpm_root_for_version(lpm_root, store_version);
    let mut packages = Vec::new();
    let mut sidecar_issues = Vec::new();
    for (link_dir, result) in store_v2.iter_link_entries_for_verify()? {
        match result {
            Ok(meta) => {
                let pkg_dir = link_dir.join("node_modules").join(&meta.name);
                packages.push(StoreVerifyEntry {
                    name: meta.name,
                    version: meta.version,
                    dir: pkg_dir,
                    inline_integrity: Some(meta.source_sri),
                    object_path: Some(meta.object_path),
                    store_version: Some(store_version),
                    tree_digest: meta.tree_digest,
                });
            }
            Err(e) => {
                // L59: link directory names live under the user's
                // store root but may have been planted by a hostile
                // same-user writer. The error text itself can carry
                // sidecar bytes (filename / parse-position previews).
                let dir_name = link_dir.file_name().map_or_else(
                    || link_dir.display().to_string(),
                    |s| s.to_string_lossy().into_owned(),
                );
                sidecar_issues.push(format!(
                    "{store_version} link {} — sidecar unreadable: {}",
                    sanitize_for_terminal(&dir_name),
                    sanitize_for_terminal(&e.to_string())
                ));
            }
        }
    }
    packages.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str(), a.dir.as_path()).cmp(&(
            &b.name,
            &b.version,
            b.dir.as_path(),
        ))
    });
    sidecar_issues.sort();
    Ok((packages, sidecar_issues))
}

fn list_virtual_object_paths(
    lpm_root: &LpmRoot,
    store_version: lpm_store::StoreVersion,
) -> Result<HashSet<(lpm_store::StoreVersion, String)>, LpmError> {
    let store_v2 = lpm_store::v2::Store::from_lpm_root_for_version(lpm_root, store_version);
    let mut object_paths = HashSet::new();
    for (_, segment) in store_v2.iter_object_dirs()? {
        object_paths.insert((store_version, format!("objects/{segment}")));
    }
    Ok(object_paths)
}

/// Compare two behavioral analyses for equivalence (ignoring timestamps and metadata).
///
/// Returns `true` if the actual tag values match. Differences in `analyzedAt`,
/// `meta.filesScanned`, or `meta.bytesScanned` are expected and ignored.
fn security_analysis_matches(
    cached: &lpm_security::behavioral::PackageAnalysis,
    fresh: &lpm_security::behavioral::PackageAnalysis,
) -> bool {
    cached.source == fresh.source
        && cached.supply_chain == fresh.supply_chain
        && cached.manifest == fresh.manifest
}

fn write_security_cache_for_verify(
    dir: &std::path::Path,
    fresh: &lpm_security::behavioral::PackageAnalysis,
    safe_name: &str,
    safe_version: &str,
) -> Result<(), String> {
    lpm_security::behavioral::write_cached_analysis(dir, fresh).map_err(|e| {
        format!(
            "{safe_name}@{safe_version} — failed to write .lpm-security.json: {}",
            sanitize_for_terminal(&e.to_string())
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Store verify ────────────────────────────────────────────────

    fn make_test_analysis() -> lpm_security::behavioral::PackageAnalysis {
        lpm_security::behavioral::PackageAnalysis {
            version: 1,
            analyzed_at: "T00:00:00Z".to_string(),
            source: lpm_security::behavioral::source::SourceTags::default(),
            supply_chain: lpm_security::behavioral::supply_chain::SupplyChainTags::default(),
            manifest: lpm_security::behavioral::manifest::ManifestTags::default(),
            meta: lpm_security::behavioral::AnalysisMeta::default(),
        }
    }

    fn test_tarball(name: &str, version: &str) -> Vec<u8> {
        use std::io::Write;

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let content = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "package/package.json", content.as_bytes())
                .unwrap();
            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&tar_data).unwrap();
        encoder.finish().unwrap()
    }

    fn seed_v2_verify_entry(
        lpm_root: &LpmRoot,
        name: &str,
        version: &str,
        create_object: bool,
    ) -> (String, String) {
        use lpm_store::v2::link_meta::{LinkMeta, LinkMetaPlatform};

        let store_v2 = lpm_store::v2::Store::from_lpm_root(lpm_root);
        let sri = lpm_store::compute_sri_hash(format!("{name}@{version}").as_bytes());
        let object_path = store_v2.paths().relative_object_path(&sri).unwrap();

        if create_object {
            store_v2
                .extract_object(&sri, &test_tarball(name, version))
                .unwrap();
        }

        let link_key = format!("{name}@{version}+0123456789abcdef");
        let link_dir = store_v2.paths().links_root().join(&link_key);
        let pkg_dir = link_dir.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "// nothing").unwrap();

        let meta = LinkMeta {
            schema: 1,
            graph_key: link_key,
            graph_key_digest_hex:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            name: name.to_string(),
            version: version.to_string(),
            source_sri: sri.clone(),
            object_path: object_path.clone(),
            tree_digest: None,
            deps: vec![],
            platform: std::sync::Arc::new(LinkMetaPlatform {
                os: "darwin".to_string(),
                cpu: "arm64".to_string(),
                libc: None,
            }),
            created_at: chrono::Utc::now(),
            last_referenced_at: chrono::Utc::now(),
        };
        meta.write_to(&link_dir).unwrap();

        (sri, object_path)
    }

    #[test]
    fn security_analysis_matches_identical() {
        let a = make_test_analysis();
        let b = a.clone();
        assert!(security_analysis_matches(&a, &b));
    }

    #[test]
    fn security_analysis_mismatch_detected() {
        let a = make_test_analysis();
        let mut b = a.clone();
        b.source.eval = true;
        assert!(!security_analysis_matches(&a, &b));
    }

    #[test]
    fn security_analysis_ignores_timestamp_differences() {
        let a = make_test_analysis();
        let mut b = a.clone();
        b.analyzed_at = "T12:00:00Z".to_string();
        b.meta.files_scanned = 999;
        // Timestamps and meta are ignored — only tags matter
        assert!(security_analysis_matches(&a, &b));
    }

    // ─── Store verify --fix end-to-end ─────────────────────────────

    #[test]
    fn verify_deep_without_fix_does_not_mutate_cache() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        // Create a package with a source file (so analysis can detect something)
        let pkg_dir = dir.path().join("v1").join("test-pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"test-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "eval('hello')").unwrap();

        // Write a stale security cache with mismatched tags (eval=false when file has eval)
        let stale = make_test_analysis();
        lpm_security::behavioral::write_cached_analysis(&pkg_dir, &stale).unwrap();
        let before = std::fs::read_to_string(pkg_dir.join(".lpm-security.json")).unwrap();

        // Verify without --fix: should NOT rewrite the cache
        run_verify(&LpmRoot::from_dir(dir.path()), &store, true, false, true).unwrap();
        let after = std::fs::read_to_string(pkg_dir.join(".lpm-security.json")).unwrap();
        assert_eq!(
            before, after,
            "verify without --fix must not mutate .lpm-security.json"
        );
    }

    #[test]
    fn verify_deep_with_fix_rewrites_stale_cache() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        // Create a package with a source file that triggers eval detection
        let pkg_dir = dir.path().join("v1").join("test-pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"test-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "eval('hello')").unwrap();

        // Write a stale security cache with all-default tags
        let stale = make_test_analysis();
        lpm_security::behavioral::write_cached_analysis(&pkg_dir, &stale).unwrap();
        let before = std::fs::read_to_string(pkg_dir.join(".lpm-security.json")).unwrap();

        // Verify WITH --fix: should rewrite the cache
        run_verify(&LpmRoot::from_dir(dir.path()), &store, true, true, true).unwrap();
        let after = std::fs::read_to_string(pkg_dir.join(".lpm-security.json")).unwrap();
        assert_ne!(
            before, after,
            "verify with --fix must rewrite stale .lpm-security.json"
        );
    }

    #[test]
    fn verify_deep_no_fix_reports_missing_cache() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        // Create a package WITHOUT any security cache
        let pkg_dir = dir.path().join("v1").join("test-pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"test-pkg","version":"1.0.0"}"#,
        )
        .unwrap();

        // Verify without --fix: should not create the cache file
        run_verify(&LpmRoot::from_dir(dir.path()), &store, true, false, true).unwrap();
        assert!(
            !pkg_dir.join(".lpm-security.json").exists(),
            "verify without --fix must not create .lpm-security.json"
        );
    }

    #[test]
    fn verify_deep_fix_creates_missing_cache() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path());

        // Create a package WITHOUT any security cache
        let pkg_dir = dir.path().join("v1").join("test-pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"test-pkg","version":"1.0.0"}"#,
        )
        .unwrap();

        // Verify WITH --fix: should create the cache file
        run_verify(&LpmRoot::from_dir(dir.path()), &store, true, true, true).unwrap();
        assert!(
            pkg_dir.join(".lpm-security.json").exists(),
            "verify with --fix must create .lpm-security.json"
        );
    }

    /// Pre-fix,
    /// `run_verify` walked `<store>/v1/` only. Under v2 the v1 dir
    /// doesn't exist, so the command silently reported zero packages
    /// even when hundreds of links sat in `<store>/v2/links/`. This
    /// test seeds a single v2 link entry (sidecar + node_modules dir +
    /// package.json) and asserts:
    ///   1. `list_v2_verify_entries` enumerates the link entry exactly.
    ///   2. `run_verify` walks the entry without error.
    ///   3. The integrity check uses the sidecar's `source_sri`
    ///      directly (no `.integrity` file in v2 link dirs).
    ///
    /// Walking `populate_link_entry` would require an extracted object
    /// directory + the full materialization pipeline; this test
    /// short-circuits by writing the sidecar via `LinkMeta::write_to`
    /// directly. Same on-disk shape, smaller test surface — and it
    /// pins the contract `iter_link_entries` consumes.
    #[test]
    fn verify_walks_v2_link_entries() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = LpmRoot::from_dir(dir.path());
        let store = PackageStore::at(dir.path().join("store"));
        let (sri, object_path) = seed_v2_verify_entry(&lpm_root, "test-pkg", "1.0.0", true);

        // Step 1: the v2 walker enumerates the entry.
        let (entries, sidecar_issues) = list_v2_verify_entries(&lpm_root).unwrap();
        assert!(sidecar_issues.is_empty(), "no sidecar issues expected");
        assert_eq!(
            entries.len(),
            1,
            "v2 walker must report the seeded link entry"
        );
        assert_eq!(entries[0].name, "test-pkg");
        assert_eq!(entries[0].version, "1.0.0");
        assert_eq!(entries[0].inline_integrity.as_deref(), Some(sri.as_str()));
        assert_eq!(
            entries[0].object_path.as_deref(),
            Some(object_path.as_str())
        );
        assert!(entries[0].dir.ends_with("node_modules/test-pkg"));

        // Step 2: end-to-end `run_verify` (deep mode, no fix). The
        // entry passes every check — directory exists, package.json
        // present, name/version match — and the call returns Ok.
        // Pre-S4-fix, this assertion would still pass (verify silently
        // walks no packages and reports "Store is empty"), but step 1
        // above caught the missing enumeration. The test exists for
        // both signals.
        run_verify(&lpm_root, &store, true, false, true)
            .expect("verify must complete cleanly with one v2 entry");
    }

    /// sanity-check that v1 and
    /// v2 entries verify side-by-side without one shadowing the other.
    /// A user mid-migration (some packages installed under v1, others
    /// under v2) sees both walked.
    #[test]
    fn verify_walks_v1_and_v2_entries_concurrently() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = LpmRoot::from_dir(dir.path());
        let store = PackageStore::at(dir.path().join("store"));

        // Seed a v1 entry.
        let v1_pkg_dir = dir.path().join("store").join("v1").join("v1-pkg@1.0.0");
        std::fs::create_dir_all(&v1_pkg_dir).unwrap();
        std::fs::write(
            v1_pkg_dir.join("package.json"),
            r#"{"name":"v1-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(v1_pkg_dir.join(".integrity"), "sha512-v1-test").unwrap();

        // Seed a v2 entry.
        seed_v2_verify_entry(&lpm_root, "v2-pkg", "2.0.0", true);

        let v1_entries = list_v1_verify_entries(&store).unwrap();
        let (v2_entries, v2_issues) = list_v2_verify_entries(&lpm_root).unwrap();
        assert_eq!(v1_entries.len(), 1);
        assert_eq!(v2_entries.len(), 1);
        assert!(v2_issues.is_empty(), "no sidecar issues expected");
        assert_eq!(v1_entries[0].name, "v1-pkg");
        assert_eq!(v2_entries[0].name, "v2-pkg");
        // V1 entries leave inline_integrity None; the verify loop
        // falls back to `read_stored_integrity`. V2 entries carry
        // it pre-resolved.
        assert!(v1_entries[0].inline_integrity.is_none());
        assert!(v2_entries[0].inline_integrity.is_some());

        run_verify(&lpm_root, &store, true, false, true)
            .expect("verify must walk both v1 and v2 entries");
    }

    #[test]
    fn verify_returns_exit_code_when_v2_referenced_object_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = LpmRoot::from_dir(dir.path());
        let store = PackageStore::at(dir.path().join("store"));

        seed_v2_verify_entry(&lpm_root, "missing-object", "1.0.0", false);

        let err = run_verify(&lpm_root, &store, false, false, true)
            .expect_err("missing referenced v2 object must surface as Err");
        assert!(matches!(err, LpmError::ExitCode(1)), "got: {err:?}");
    }

    /// L56: corrupted entries must surface as `LpmError::ExitCode(1)`
    /// so CI gates built on `$?` see the failure. Pre-fix the function
    /// returned `Ok(())` regardless of how many corrupted entries it
    /// found.
    #[test]
    fn verify_returns_exit_code_when_corrupted_entries_present() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));

        // Seed a v1 entry that's missing package.json.
        let pkg_dir = dir.path().join("store").join("v1").join("test-pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join("README.md"), "no manifest").unwrap();

        let err = run_verify(&LpmRoot::from_dir(dir.path()), &store, false, false, true)
            .expect_err("corrupted entry must surface as Err");
        assert!(
            matches!(err, LpmError::ExitCode(1)),
            "expected ExitCode(1), got {err:?}"
        );
    }

    /// L57: a v2 link directory with a malformed sidecar must reach
    /// the verifier's corrupted list. Pre-fix `iter_link_entries`
    /// silently filtered these out and verify reported "Store is
    /// empty" or whatever count remained.
    #[test]
    fn verify_reports_malformed_v2_sidecar_as_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_root = LpmRoot::from_dir(dir.path());

        // Seed a v2 link directory with a broken sidecar.
        let v2_links_root = dir.path().join("store").join("v2").join("links");
        let link_dir = v2_links_root.join("broken-pkg@1.0.0+0123456789abcdef");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::fs::write(link_dir.join(".lpm-link-meta.json"), b"{not valid json").unwrap();

        let (entries, sidecar_issues) = list_v2_verify_entries(&lpm_root).unwrap();
        assert!(entries.is_empty(), "malformed entry must not be verified");
        assert_eq!(sidecar_issues.len(), 1, "got: {sidecar_issues:?}");
        assert!(
            sidecar_issues[0].contains("broken-pkg"),
            "issue must name the affected link directory: {}",
            sidecar_issues[0]
        );
        assert!(
            sidecar_issues[0].contains("sidecar unreadable"),
            "issue must describe the failure type: {}",
            sidecar_issues[0]
        );
    }

    /// L57: malformed sidecars must drive the same `ExitCode(1)` exit
    /// as v1 corruption — proves the L56 + L57 contracts compose.
    #[test]
    fn verify_returns_exit_code_when_v2_sidecar_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));

        let link_dir = dir
            .path()
            .join("store")
            .join("v2")
            .join("links")
            .join("broken-pkg@1.0.0+0123456789abcdef");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::fs::write(link_dir.join(".lpm-link-meta.json"), b"{not valid json").unwrap();

        let err = run_verify(&LpmRoot::from_dir(dir.path()), &store, false, false, true)
            .expect_err("malformed v2 sidecar must surface as Err");
        assert!(matches!(err, LpmError::ExitCode(1)), "got: {err:?}");
    }

    /// L59: `truncate_chars_safe` slices on char boundaries — a
    /// poisoned non-ASCII SRI prefix won't panic the diagnostic path
    /// the way the pre-fix `&s[..s.len().min(20)]` did.
    #[test]
    fn truncate_chars_safe_handles_non_ascii_without_panic() {
        // Each 'é' is two bytes; 30 of them is 60 bytes — pre-fix
        // `&s[..20]` would slice mid-codepoint and panic.
        let s = "é".repeat(30);
        let preview = truncate_chars_safe(&s, 20);
        assert_eq!(preview.chars().count(), 20);
    }

    /// L59: shorter strings pass through unchanged so the helper
    /// doesn't over-trim legit short integrity prefixes.
    #[test]
    fn truncate_chars_safe_keeps_short_strings_intact() {
        assert_eq!(truncate_chars_safe("sha512-abc", 20), "sha512-abc");
        assert_eq!(truncate_chars_safe("", 20), "");
    }

    /// L59: when a package's directory name carries ESC/BEL/control
    /// bytes, sanitize_for_terminal scrubs them before the corruption
    /// issue is appended. Renders the post-fix invariant via the
    /// public sanitizer applied to the same bytes the verifier reads.
    #[test]
    fn verify_strings_pass_through_terminal_sanitizer() {
        let raw = "pkg\x1b]8;;file:///etc/passwd\x07evil";
        let safe = sanitize_for_terminal(raw);
        assert!(!safe.contains('\x1b'), "ESC byte must be scrubbed");
        assert!(!safe.contains('\x07'), "BEL byte must be scrubbed");
        // Printable surrounding characters survive.
        assert!(safe.starts_with("pkg"));
        assert!(safe.ends_with("evil"));
    }

    /// The base envelope distinguishes basic presence from deep marker
    /// consistency. CAS verification adds the exact byte-integrity result.
    #[test]
    fn verify_envelope_defers_bytes_integrity_to_cas_verification() {
        let basic = build_verify_envelope(true, false, 3, 3, 0, &[], 0, 0);
        assert_eq!(basic["check_kind"].as_str(), Some("presence"));
        assert_eq!(basic["legacy_check_kind"].as_str(), Some("presence"));
        assert_eq!(basic["bytes_integrity_recomputed"].as_bool(), Some(false));
        assert!(
            basic.get("securityMismatches").is_none(),
            "basic mode omits security fields"
        );

        let deep = build_verify_envelope(true, true, 3, 3, 0, &[], 0, 0);
        assert_eq!(
            deep["check_kind"].as_str(),
            Some("lockfile_marker_consistency")
        );
        assert_eq!(deep["bytes_integrity_recomputed"].as_bool(), Some(false));
        assert_eq!(
            deep["legacy_check_kind"].as_str(),
            Some("lockfile_marker_consistency")
        );
        assert_eq!(deep["securityMismatches"].as_u64(), Some(0));
        assert_eq!(deep["securityReanalyzed"].as_u64(), Some(0));
    }

    #[test]
    fn deep_cas_verification_reports_actual_blob_rehashing() {
        let mut envelope = build_verify_envelope(true, true, 0, 0, 0, &[], 0, 0);
        let verification = lpm_store::v3::FileCasVerification {
            blobs: 2,
            blobs_rehashed: 2,
            ..Default::default()
        };

        attach_cas_verification(&mut envelope, &verification, true);

        assert_eq!(envelope["bytes_integrity_recomputed"].as_bool(), Some(true));
        assert_eq!(envelope["cas"]["check_kind"].as_str(), Some("content_hash"));
        assert_eq!(
            envelope["cas"]["blob_integrity_recomputed"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn cas_metadata_keeps_store_verify_out_of_the_empty_store_path() {
        let counts = StoreVerifyCounts {
            links: 0,
            objects: 0,
            sources: 0,
            trees: 1,
            blobs: 0,
            materialized: 0,
        };

        assert!(!counts.is_empty());
    }

    /// Corrupted entries surface in the JSON envelope with
    /// `success: false` AND the new `check_kind` / bytes flag — the
    /// "verify returns ExitCode(1) on corruption" contract composes
    /// with the renamed scope.
    #[test]
    fn verify_envelope_surfaces_corruption_with_consistent_check_kind() {
        let issues = vec!["pkg@1.0.0 — missing package.json".to_string()];
        let env = build_verify_envelope(false, true, 5, 5, 0, &issues, 0, 0);
        assert_eq!(env["success"].as_bool(), Some(false));
        assert_eq!(env["corrupted"].as_u64(), Some(1));
        assert_eq!(
            env["check_kind"].as_str(),
            Some("lockfile_marker_consistency")
        );
        assert_eq!(env["bytes_integrity_recomputed"].as_bool(), Some(false));
        assert_eq!(env["issues"][0].as_str(), issues[0].as_str().into());
    }

    /// L56: a clean store must continue to return Ok — proves the
    /// success contract widens for corruption only, not blanket.
    #[test]
    fn verify_returns_ok_for_clean_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = PackageStore::at(dir.path().join("store"));

        // Seed one healthy v1 entry.
        let pkg_dir = dir.path().join("store").join("v1").join("ok-pkg@1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"ok-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "// nothing").unwrap();

        run_verify(&LpmRoot::from_dir(dir.path()), &store, false, false, true)
            .expect("clean store must verify Ok");
    }

    // ─── F4 — verify dedup-count contract ───────────────────────────

    fn verify_entry_stub(name: &str, version: &str) -> StoreVerifyEntry {
        StoreVerifyEntry {
            name: name.to_string(),
            version: version.to_string(),
            dir: std::path::PathBuf::from(format!("/tmp/{name}@{version}")),
            inline_integrity: None,
            object_path: None,
            store_version: None,
            tree_digest: None,
        }
    }

    /// Empty input — no entries, no duplicates, no unique coords. The
    /// run_verify empty-store branch short-circuits before this is
    /// called in production, but the helper must still be safe to
    /// invoke on an empty slice.
    #[test]
    fn f4_compute_verify_dedup_counts_empty() {
        assert_eq!(compute_verify_dedup_counts(&[]), (0, 0));
    }

    /// All entries have distinct coords — `duplicated_count` is 0
    /// and the human-output line falls into the "no duplication"
    /// branch (no parenthetical secondary count).
    #[test]
    fn f4_compute_verify_dedup_counts_all_distinct() {
        let entries = vec![
            verify_entry_stub("a", "1.0.0"),
            verify_entry_stub("b", "2.0.0"),
            verify_entry_stub("c", "3.0.0"),
        ];
        let (unique, duplicated) = compute_verify_dedup_counts(&entries);
        assert_eq!(unique, 3);
        assert_eq!(duplicated, 0);
    }

    /// **The load-bearing F4 case.** A `(name, version)` legitimately
    /// shows up in BOTH v1 (post-migration) and v2 (post-install) for
    /// the same package — each entry is independently verifiable, the
    /// `verified` count stays accurate, but `unique_coords` reports
    /// the user-meaningful "actual distinct packages on disk" number.
    /// Without this distinction the human-output line said
    /// "{N} packages verified" where N was double-counted.
    #[test]
    fn f4_compute_verify_dedup_counts_dedupe_v1_v2_overlap() {
        let entries = vec![
            // v1 + v2 entry for the same package — the migration
            // overlap case.
            verify_entry_stub("lodash", "4.17.21"),
            verify_entry_stub("lodash", "4.17.21"),
            // A standalone package (no overlap).
            verify_entry_stub("react", "18.0.0"),
            // Multi-source-same-coords case: two graph keys for the
            // same coords.
            verify_entry_stub("typescript", "5.0.0"),
            verify_entry_stub("typescript", "5.0.0"),
            verify_entry_stub("typescript", "5.0.0"),
        ];
        let (unique, duplicated) = compute_verify_dedup_counts(&entries);
        assert_eq!(unique, 3, "lodash + react + typescript = 3 unique coords");
        assert_eq!(
            duplicated, 3,
            "1 dup of lodash + 2 extra typescript copies = 3 duplicated entries"
        );
    }

    /// `lpm store clean` wipes every supported store generation.
    #[test]
    fn store_clean_wipes_all_store_generations() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());

        // Seed every store generation with byte content.
        let v1 = root.store_v1();
        std::fs::create_dir_all(&v1).unwrap();
        std::fs::write(v1.join("v1-seed.bin"), b"v1-data").unwrap();

        let v2 = root.store_root().join("v2");
        std::fs::create_dir_all(&v2).unwrap();
        std::fs::write(v2.join("v2-seed.bin"), b"v2-data").unwrap();
        let v3 = root.store_root().join("v3");
        std::fs::create_dir_all(&v3).unwrap();
        std::fs::write(v3.join("v3-seed.bin"), b"v3-data").unwrap();

        // Sanity — both exist before run_clean.
        assert!(v1.exists() && v2.exists() && v3.exists());

        run_clean(&root, true).unwrap();

        assert!(!v1.exists(), "v1 store directory must be wiped");
        assert!(
            !v2.exists(),
            "v2 store directory MUST be wiped — pre-fix this was the silent gap"
        );
        assert!(!v3.exists(), "v3 store directory must be wiped");
    }

    /// Empty-store branch handles the case where no generation
    /// has any state on disk (fresh install, or a prior `clean` was
    /// already run). Must succeed silently.
    #[test]
    fn store_clean_is_a_noop_when_every_generation_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        // No version directory exists; `run_clean` must not error.
        run_clean(&root, true).expect("empty store must not error");
    }

    /// Mixed: only v2 exists. A v1-only early return
    /// would have hit the empty-store branch and printed "already
    /// empty" while leaving v2 intact. Post-fix: v2 gets wiped.
    #[test]
    fn store_clean_wipes_v2_when_v1_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        let v2 = root.store_root().join("v2");
        std::fs::create_dir_all(&v2).unwrap();
        std::fs::write(v2.join("seed.bin"), b"v2-data").unwrap();
        assert!(v2.exists());

        run_clean(&root, true).unwrap();
        assert!(!v2.exists(), "v2 must be wiped even when v1 is absent");
    }

    #[test]
    fn store_clean_json_retains_legacy_path_alias() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        let v1 = root.store_v1();
        let v2 = root.store_root().join("v2");

        let v3 = root.store_root().join("v3");
        let payload = clean_json_payload(&v1, &v2, &v3, 5, 7, 11);
        assert_eq!(
            payload["path"].as_str(),
            Some(v1.to_string_lossy().as_ref())
        );
        assert_eq!(
            payload["v1_path"].as_str(),
            Some(v1.to_string_lossy().as_ref())
        );
        assert_eq!(
            payload["v2_path"].as_str(),
            Some(v2.to_string_lossy().as_ref())
        );
        assert_eq!(
            payload["v3_path"].as_str(),
            Some(v3.to_string_lossy().as_ref())
        );
        assert_eq!(payload["removed_bytes"].as_u64(), Some(23));
    }

    /// Versions matter: same name across two versions counts as TWO
    /// unique coords, never collapsed. Defense-in-depth against an
    /// accidental name-only dedupe ever sneaking into the helper.
    #[test]
    fn f4_compute_verify_dedup_counts_distinguishes_versions() {
        let entries = vec![
            verify_entry_stub("react", "17.0.0"),
            verify_entry_stub("react", "18.0.0"),
            verify_entry_stub("react", "19.0.0"),
        ];
        let (unique, duplicated) = compute_verify_dedup_counts(&entries);
        assert_eq!(unique, 3);
        assert_eq!(duplicated, 0);
    }
}
