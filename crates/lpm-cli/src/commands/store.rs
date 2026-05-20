use crate::output;
use lpm_common::color::Painted;
use lpm_common::{
    LpmError, LpmRoot, format_bytes, sanitize_for_terminal, with_exclusive_lock, with_shared_lock,
};
use lpm_store::PackageStore;

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
                println!("{path}");
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

/// Blunt store wipe — removes `~/.lpm/store/v1/` AND
/// `~/.lpm/store/v2/` in their entirety.
///
/// This is the phase-37 counterpart to the old `lpm cache clean`
/// behavior: an explicit, scoped, named command for the rare "nuke
/// everything" workflow. For everyday maintenance use
/// `lpm cache prune --apply`, which is reference-aware and won't evict packages
/// currently referenced by a project lockfile.
///
///
/// Pre-fix this only wiped `v1/`, leaving `v2/links/` and
/// `v2/objects/` intact. Under the v2-default install path that
/// shippedb, that meant `lpm store clean` was a silent
/// near-no-op for users running the default — the tarball CAS, link
/// entries, and patched-bytes link variants survived. The verify
/// command now speaks in merged v1+v2 terms (F4); `clean` mirrors
/// that surface so the human-output line "Wiped package store" is
/// truthful again.
///
/// The two version subdirectories are the unit of removal so the
/// outer `store/` dir (`.gc.lock`, other control files) stays intact.
fn run_clean(root: &LpmRoot, json_output: bool) -> Result<(), LpmError> {
    let v1 = root.store_v1();
    let v2 = root.store_root().join("v2");

    let v1_existed = v1.exists();
    let v2_existed = v2.exists();

    if !v1_existed && !v2_existed {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&clean_json_payload(&v1, &v2, 0, 0)).unwrap()
            );
        } else {
            output::info("Store is already empty");
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

    if v1_existed {
        std::fs::remove_dir_all(&v1)?;
    }
    if v2_existed {
        std::fs::remove_dir_all(&v2)?;
    }

    let bytes_before = v1_bytes + v2_bytes;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&clean_json_payload(&v1, &v2, v1_bytes, v2_bytes))
                .unwrap()
        );
    } else {
        output::success(&format!(
            "Wiped package store ({})",
            format_bytes(bytes_before)
        ));
        output::info("Use `lpm install` to repopulate from lockfiles.");
    }

    Ok(())
}

fn clean_json_payload(
    v1: &std::path::Path,
    v2: &std::path::Path,
    v1_removed_bytes: u64,
    v2_removed_bytes: u64,
) -> serde_json::Value {
    let removed_bytes = v1_removed_bytes + v2_removed_bytes;
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
        "v1_removed_bytes": v1_removed_bytes,
        "v2_removed_bytes": v2_removed_bytes,
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
/// `v2` link sidecar's `source_sri`) against the current project
/// lockfile's claimed integrity for that package. Detects marker
/// drift and lockfile poisoning that would change the claimed source
/// hash.
///
/// **Scope limit:** `--deep` does NOT re-hash the extracted on-disk
/// bytes. The `.integrity` marker is the tarball-time digest; a
/// post-extraction tamper that leaves the marker untouched looks
/// healthy to `--deep`. Treat this command as a lockfile-marker
/// consistency check, not a bytes-on-disk attestation. A byte-integrity
/// recompute would need a Merkle digest of the extracted directory and
/// is out of scope for the current store layout.
///
/// Fix mode (`--fix`): auto-repair stale `.lpm-security.json`
/// behavioral caches. Without `--fix`, verify is read-only.
///
/// Walks both the v1 store (`<store>/v1/<safe>@<ver>/`) AND the v2
/// link entries (`<store>/v2/links/<key>/node_modules/<name>/`).
fn run_verify(
    lpm_root: &LpmRoot,
    store: &PackageStore,
    deep: bool,
    fix: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let mut packages: Vec<StoreVerifyEntry> = list_v1_verify_entries(store)?;
    let (v2_entries, mut sidecar_issues) = list_v2_verify_entries(lpm_root)?;
    packages.extend(v2_entries);

    if packages.is_empty() && sidecar_issues.is_empty() {
        if json_output {
            // F4: empty-store envelope mirrors the populated-store
            // shape so downstream consumers don't need to special-case
            // the zero path. `verified` retained as an alias of
            // `entries_verified` for the legacy field name.
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "entries_verified": 0,
                    "verified": 0,
                    "unique_coords": 0,
                    "duplicated_entries": 0,
                    "corrupted": 0,
                    "issues": [],
                }))
                .unwrap()
            );
        } else {
            output::info("Store is empty — nothing to verify");
        }
        return Ok(());
    }

    // In deep mode, load lockfile integrity hashes for cross-checking
    let lockfile_integrity: std::collections::HashMap<String, String> = if deep {
        let cwd = std::env::current_dir().unwrap_or_default();
        let lockfile_path = cwd.join("lpm.lock");
        if lockfile_path.exists() {
            lpm_lockfile::Lockfile::read_fast(&lockfile_path)
                .map(|lf| {
                    lf.packages
                        .iter()
                        .filter_map(|p| {
                            p.integrity
                                .as_ref()
                                .map(|i| (format!("{}@{}", p.name, p.version), i.clone()))
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            std::collections::HashMap::new()
        }
    } else {
        std::collections::HashMap::new()
    };

    let mut verified = 0u32;
    let mut corrupted: Vec<String> = Vec::new();
    // L57: v2 link directories whose sidecar was missing/malformed/
    // schema-mismatched/unsafe-name reach us as pre-seeded corruption
    // entries. They never become "verified."
    corrupted.append(&mut sidecar_issues);
    let mut security_mismatches = 0u32;
    let mut security_reanalyzed = 0u32;

    for entry in &packages {
        let StoreVerifyEntry {
            name,
            version,
            dir,
            inline_integrity,
        } = entry;
        // L59: every state-derived field that may carry sidecar / dir
        // / package.json control bytes goes through sanitize_for_terminal
        // before format!. Without this a tampered sidecar can ride
        // ESC/BEL/OSC sequences into the human emitter.
        let safe_name = sanitize_for_terminal(name);
        let safe_version = sanitize_for_terminal(version);

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
            match std::fs::read_to_string(&pkg_json_path) {
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
                            if let Err(e) =
                                lpm_security::behavioral::write_cached_analysis(dir, &fresh)
                            {
                                tracing::warn!(
                                    "failed to re-write .lpm-security.json for {name}@{version}: {e}"
                                );
                            } else {
                                security_reanalyzed += 1;
                            }
                            if !json_output {
                                eprintln!(
                                    "    {} {name}@{version} — security analysis mismatch (fixed)",
                                    "⚠".yellow()
                                );
                            }
                        } else if !json_output {
                            eprintln!(
                                "    {} {name}@{version} — security analysis mismatch (use --fix to refresh)",
                                "⚠".yellow()
                            );
                        }
                    }
                }
                None => {
                    security_mismatches += 1;
                    if fix {
                        if let Err(e) = lpm_security::behavioral::write_cached_analysis(dir, &fresh)
                        {
                            tracing::warn!(
                                "failed to write .lpm-security.json for {name}@{version}: {e}"
                            );
                        } else {
                            security_reanalyzed += 1;
                        }
                        if !json_output {
                            eprintln!(
                                "    {} {name}@{version} — missing security cache (fixed)",
                                "⚠".yellow()
                            );
                        }
                    } else if !json_output {
                        eprintln!(
                            "    {} {name}@{version} — missing security cache (use --fix to generate)",
                            "⚠".yellow()
                        );
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
        let result = build_verify_envelope(
            success,
            deep,
            verified,
            unique_coords,
            duplicated_count,
            &corrupted,
            security_mismatches,
            security_reanalyzed,
        );
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else if corrupted.is_empty() {
        // F4: noun is "store entries" (truthful for v1+v2 merged
        // walks); secondary `(N unique packages)` parenthetical when
        // the two counts differ — almost always during a v1→v2
        // migration or after a multi-source-same-coords install.
        let mut msg = if duplicated_count > 0 {
            format!(
                "{verified} store entries verified ({unique_coords} unique packages, {duplicated_count} duplicated across v1+v2 / graph keys), all OK"
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
            output::warn(&format!(
                "{verified} store entries verified, {security_mismatches} security analysis mismatch{} (use --fix to refresh)",
                if security_mismatches == 1 { "" } else { "es" }
            ));
        } else if deep && security_mismatches > 0 && fix {
            output::warn(&format!(
                "{verified} store entries verified, {security_mismatches} security analysis mismatch{} (fixed)",
                if security_mismatches == 1 { "" } else { "es" }
            ));
        } else {
            output::success(&msg);
        }
        if deep {
            // Make the scope explicit so users don't assume a clean
            // exit attests to bytes-on-disk integrity.
            output::info(
                "Note: --deep verifies lockfile↔marker consistency, not extracted-bytes \
                 integrity. Re-hashing the extracted directory contents is not implemented.",
            );
        }
    } else {
        output::warn(&format!("{} corrupted, {} OK", corrupted.len(), verified));
        for issue in &corrupted {
            eprintln!("    {} {issue}", "⚠".yellow());
        }
        if deep && security_mismatches > 0 {
            let suffix = if fix { "fixed" } else { "use --fix to refresh" };
            eprintln!(
                "    {} {security_mismatches} security analysis mismatch{} ({suffix})",
                "⚠".yellow(),
                if security_mismatches == 1 { "" } else { "es" }
            );
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

/// derive the
/// `(unique_coords, duplicated_count)` pair from the merged v1+v2
/// entry list. Pure compute over already-walked input, factored out
/// for unit testability.
///
/// `unique_coords` counts distinct `(name, version)` pairs across the
/// whole list. `duplicated_count` is `entries.len() - unique_coords`,
/// surfaced separately so the human-output line can describe what
/// drove the divergence (almost always "N entries split across v1+v2
/// during a migration" or "N entries split across graph keys via
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

/// Build the JSON envelope `lpm store verify --json` emits to stdout.
/// Pure compute over already-walked input, factored out so tests can
/// assert the contract directly without capturing stdout.
///
/// `check_kind` names exactly what was verified — basic presence vs.
/// lockfile-marker consistency — so CI/agent consumers don't infer
/// "byte integrity verified" from a `--deep` envelope.
/// `bytes_integrity_recomputed` stays `false` until a Merkle-digest
/// pass over the extracted directory contents is implemented.
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
    let store_v2 = lpm_store::v2::Store::from_lpm_root(lpm_root);
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
                    "v2 link {} — sidecar unreadable: {}",
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
        use lpm_store::v2::link_meta::LinkMeta;

        let dir = tempfile::tempdir().unwrap();
        let lpm_root = LpmRoot::from_dir(dir.path());
        let store = PackageStore::at(dir.path().join("store"));

        // Synthesize a v2 link entry on disk. `iter_link_entries`
        // walks `<lpm_root>/store/v2/links/<key>/` and reads the
        // `.lpm-link-meta.json` sidecar; the package dir lives at
        // `links/<key>/node_modules/<name>/`.
        let v2_links_root = dir.path().join("store").join("v2").join("links");
        let link_dir = v2_links_root.join("test-pkg@1.0.0+0123456789abcdef");
        let pkg_dir = link_dir.join("node_modules").join("test-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name":"test-pkg","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(pkg_dir.join("index.js"), "// nothing").unwrap();

        // Write a sidecar matching the on-disk layout. `write_to`
        // serializes via the public LinkMeta JSON schema; the
        // arbitrary `graph_key` / digest values here don't matter for
        // verify — only `name` / `version` / `source_sri` are read.
        let meta = LinkMeta {
            schema: 1,
            graph_key: "test-pkg@1.0.0+0123456789abcdef".to_string(),
            graph_key_digest_hex:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            name: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            source_sri: "sha512-test-fake".to_string(),
            object_path: "objects/sha512-test-fake".to_string(),
            deps: vec![],
            platform: std::sync::Arc::new(lpm_store::v2::link_meta::LinkMetaPlatform {
                os: "darwin".to_string(),
                cpu: "arm64".to_string(),
                libc: None,
            }),
            created_at: chrono::Utc::now(),
            last_referenced_at: chrono::Utc::now(),
        };
        meta.write_to(&link_dir).unwrap();

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
        assert_eq!(
            entries[0].inline_integrity.as_deref(),
            Some("sha512-test-fake")
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
        use lpm_store::v2::link_meta::LinkMeta;

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
        let v2_link_dir = dir
            .path()
            .join("store")
            .join("v2")
            .join("links")
            .join("v2-pkg@2.0.0+abcdef0123456789");
        let v2_pkg_dir = v2_link_dir.join("node_modules").join("v2-pkg");
        std::fs::create_dir_all(&v2_pkg_dir).unwrap();
        std::fs::write(
            v2_pkg_dir.join("package.json"),
            r#"{"name":"v2-pkg","version":"2.0.0"}"#,
        )
        .unwrap();
        let meta = LinkMeta {
            schema: 1,
            graph_key: "v2-pkg@2.0.0+abcdef0123456789".to_string(),
            graph_key_digest_hex:
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            name: "v2-pkg".to_string(),
            version: "2.0.0".to_string(),
            source_sri: "sha512-v2-test".to_string(),
            object_path: "objects/sha512-v2-test".to_string(),
            deps: vec![],
            platform: std::sync::Arc::new(lpm_store::v2::link_meta::LinkMetaPlatform {
                os: "darwin".to_string(),
                cpu: "arm64".to_string(),
                libc: None,
            }),
            created_at: chrono::Utc::now(),
            last_referenced_at: chrono::Utc::now(),
        };
        meta.write_to(&v2_link_dir).unwrap();

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

    /// The `--json` envelope distinguishes the basic presence check
    /// from `--deep` lockfile-marker consistency, and never claims
    /// bytes-on-disk integrity was recomputed. CI/agent consumers can
    /// read the field instead of inferring depth from argv.
    #[test]
    fn verify_envelope_carries_check_kind_and_bytes_integrity_flag() {
        let basic = build_verify_envelope(true, false, 3, 3, 0, &[], 0, 0);
        assert_eq!(basic["check_kind"].as_str(), Some("presence"));
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
        assert_eq!(deep["securityMismatches"].as_u64(), Some(0));
        assert_eq!(deep["securityReanalyzed"].as_u64(), Some(0));
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

    /// —
    /// `lpm store clean` MUST wipe BOTH `v1/` and `v2/`. Pre-fix it
    /// was a v1-only wipe; under the v2-default install path that
    /// meant the tarball CAS, link entries, and patched-bytes link
    /// variants all survived a "clean" — silently misleading the
    /// user looking at an in-flight migration.
    #[test]
    fn f3_review_run_clean_wipes_both_v1_and_v2() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());

        // Seed both store generations with byte content.
        let v1 = root.store_v1();
        std::fs::create_dir_all(&v1).unwrap();
        std::fs::write(v1.join("v1-seed.bin"), b"v1-data").unwrap();

        let v2 = root.store_root().join("v2");
        std::fs::create_dir_all(&v2).unwrap();
        std::fs::write(v2.join("v2-seed.bin"), b"v2-data").unwrap();

        // Sanity — both exist before run_clean.
        assert!(v1.exists() && v2.exists());

        run_clean(&root, true).unwrap();

        assert!(!v1.exists(), "v1 store directory must be wiped");
        assert!(
            !v2.exists(),
            "v2 store directory MUST be wiped — pre-fix this was the silent gap"
        );
    }

    /// Empty-store branch handles the case where neither generation
    /// has any state on disk (fresh install, or a prior `clean` was
    /// already run). Must succeed silently.
    #[test]
    fn f3_review_run_clean_empty_store_is_a_silent_noop() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        // Neither v1 nor v2 dir exists; `run_clean` must not error.
        run_clean(&root, true).expect("empty store must not error");
    }

    /// Mixed: only v2 exists (the post-default install
    /// state). The v1-only `if !v1.exists()` early-return pre-fix
    /// would have hit the empty-store branch and printed "already
    /// empty" while leaving v2 intact. Post-fix: v2 gets wiped.
    #[test]
    fn f3_review_run_clean_wipes_v2_when_v1_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        let v2 = root.store_root().join("v2");
        std::fs::create_dir_all(&v2).unwrap();
        std::fs::write(v2.join("seed.bin"), b"v2-data").unwrap();
        assert!(v2.exists());

        run_clean(&root, true).unwrap();
        assert!(
            !v2.exists(),
            "v2 must be wiped even when v1 is absent — pre-fix this was the \
             silent-no-op case for the default v2 install path"
        );
    }

    #[test]
    fn f3_review_clean_json_retains_legacy_path_alias() {
        let dir = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(dir.path());
        let v1 = root.store_v1();
        let v2 = root.store_root().join("v2");

        let payload = clean_json_payload(&v1, &v2, 5, 7);
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
        assert_eq!(payload["removed_bytes"].as_u64(), Some(12));
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
