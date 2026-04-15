use crate::output;
use lpm_common::{LpmError, LpmRoot, format_bytes, with_exclusive_lock};
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::collections::HashSet;

/// Manage the global content-addressable package store.
///
/// Actions: verify, list, path, gc, clean.
pub async fn run(
    action: &str,
    deep: bool,
    dry_run: bool,
    older_than: Option<&str>,
    force: bool,
    fix: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let store = PackageStore::default_location()?;

    // `verify` / `list` / `path` are read-only and do not need the lock.
    // `gc` and `clean` are destructive and must serialize through the
    // store-maintenance lock so concurrent invocations can't tear the
    // tree down on top of each other.
    //
    // Note: coordinating destructive store ops with in-flight *installs*
    // requires the install pipeline to take a shared lock on this same
    // path during extraction. That wiring lives in M3 alongside the
    // global-install transaction. For now, M1 closes the
    // destructive-vs-destructive race; install-vs-destructive is a known
    // M3 deliverable.
    match action {
        "verify" => run_verify(&store, deep, fix, json_output),
        "list" | "ls" => run_list(&store, json_output),
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
        "gc" => {
            let root = LpmRoot::from_env()?;
            with_exclusive_lock(root.store_gc_lock(), || {
                run_gc(&store, dry_run, older_than, force, json_output)
            })
        }
        "clean" => {
            let root = LpmRoot::from_env()?;
            with_exclusive_lock(root.store_gc_lock(), || run_clean(&root, json_output))
        }
        _ => Err(LpmError::Store(format!(
            "unknown store action: {action}. Available: verify, list, path, gc, clean"
        ))),
    }
}

/// Blunt store wipe — removes `~/.lpm/store/v1/` in its entirety.
///
/// This is the phase-37 counterpart to the old `lpm cache clean` behavior:
/// an explicit, scoped, named command for the rare "nuke everything"
/// workflow. For everyday maintenance use `lpm store gc`, which is
/// reference-aware and won't evict packages currently referenced by a
/// project lockfile.
///
/// The v1 subdirectory is the unit of removal so the outer `store/` dir
/// (which may contain `.gc.lock` and — post-M3 — other control files)
/// remains intact.
fn run_clean(root: &LpmRoot, json_output: bool) -> Result<(), LpmError> {
    let v1 = root.store_v1();

    if !v1.exists() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "removed_bytes": 0,
                    "removed": format_bytes(0),
                    "path": v1.display().to_string(),
                }))
                .unwrap()
            );
        } else {
            output::info("Store is already empty");
        }
        return Ok(());
    }

    let bytes_before = crate::commands::cache::dir_size(&v1).unwrap_or(0);
    std::fs::remove_dir_all(&v1)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "removed_bytes": bytes_before,
                "removed": format_bytes(bytes_before),
                "path": v1.display().to_string(),
            }))
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

/// Verify integrity of all packages in the store.
///
/// Basic mode: checks that each package directory has a `package.json` and is non-empty.
/// Deep mode (`--deep`): additionally parses `package.json` to validate name/version consistency
/// and verifies that the directory name matches the declared name@version.
/// Fix mode (`--fix`): auto-repair issues like stale security caches. Without `--fix`, verify is read-only.
fn run_verify(
    store: &PackageStore,
    deep: bool,
    fix: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let packages = list_store_verify_entries(store)?;

    if packages.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "verified": 0,
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
    let mut security_mismatches = 0u32;
    let mut security_reanalyzed = 0u32;

    for (name, version) in &packages {
        let dir = store.package_dir(name, version);

        // Check 1: directory exists
        if !dir.exists() {
            corrupted.push(format!("{name}@{version} — directory missing"));
            continue;
        }

        // Check 2: package.json exists
        let pkg_json_path = dir.join("package.json");
        if !pkg_json_path.exists() {
            corrupted.push(format!("{name}@{version} — missing package.json"));
            continue;
        }

        // Check 3: directory is non-empty (has at least package.json + something else,
        // or at minimum package.json itself)
        let file_count = match std::fs::read_dir(&dir) {
            Ok(entries) => entries.count(),
            Err(e) => {
                corrupted.push(format!("{name}@{version} — unreadable directory: {e}"));
                continue;
            }
        };

        if file_count == 0 {
            corrupted.push(format!("{name}@{version} — empty directory"));
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
										"{name}@{version} — package.json name mismatch: declared '{declared_name}'"
									));
                                continue;
                            }
                            // Validate version matches
                            if let Some(declared_version) =
                                pkg.get("version").and_then(|v| v.as_str())
                                && declared_version != version
                            {
                                corrupted.push(format!(
										"{name}@{version} — package.json version mismatch: declared '{declared_version}'"
									));
                                continue;
                            }
                        }
                        Err(e) => {
                            corrupted.push(format!("{name}@{version} — invalid package.json: {e}"));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    corrupted.push(format!("{name}@{version} — unreadable package.json: {e}"));
                    continue;
                }
            }

            // Verify integrity hash: compare stored .integrity with lockfile
            let key = format!("{name}@{version}");
            if let Some(expected_integrity) = lockfile_integrity.get(&key) {
                match lpm_store::read_stored_integrity(&dir) {
                    Some(stored) => {
                        if stored != *expected_integrity {
                            corrupted.push(format!(
								"{name}@{version} — integrity mismatch: stored '{}...' != lockfile '{}...'",
								&stored[..stored.len().min(20)],
								&expected_integrity[..expected_integrity.len().min(20)],
							));
                            continue;
                        }
                    }
                    None => {
                        // No .integrity file — package was stored before integrity tracking.
                        // Not an error, but noted at debug level.
                        tracing::debug!(
                            "{name}@{version}: no .integrity file (pre-integrity store)"
                        );
                    }
                }
            }

            // Security cross-check: re-run behavioral analysis and compare with cached.
            // Read-only by default — only writes when --fix is passed.
            let cached = lpm_security::behavioral::read_cached_analysis(&dir);
            let fresh = lpm_security::behavioral::analyze_package(&dir);

            match cached {
                Some(ref cached_analysis) => {
                    if !security_analysis_matches(cached_analysis, &fresh) {
                        security_mismatches += 1;
                        if fix {
                            if let Err(e) =
                                lpm_security::behavioral::write_cached_analysis(&dir, &fresh)
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
                        if let Err(e) =
                            lpm_security::behavioral::write_cached_analysis(&dir, &fresh)
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

    if json_output {
        let mut result = serde_json::json!({
            "success": true,
            "verified": verified,
            "corrupted": corrupted.len(),
            "issues": corrupted,
        });
        if deep {
            result["securityMismatches"] = serde_json::json!(security_mismatches);
            result["securityReanalyzed"] = serde_json::json!(security_reanalyzed);
        }
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else if corrupted.is_empty() {
        let mut msg = format!("{verified} packages verified, all OK");
        if deep && security_reanalyzed > 0 {
            msg.push_str(&format!(
                " ({security_reanalyzed} security cache{} refreshed)",
                if security_reanalyzed == 1 { "" } else { "s" }
            ));
        }
        if deep && security_mismatches > 0 && !fix {
            output::warn(&format!(
                "{verified} packages verified, {security_mismatches} security analysis mismatch{} (use --fix to refresh)",
                if security_mismatches == 1 { "" } else { "es" }
            ));
        } else if deep && security_mismatches > 0 && fix {
            output::warn(&format!(
                "{verified} packages verified, {security_mismatches} security analysis mismatch{} (fixed)",
                if security_mismatches == 1 { "" } else { "es" }
            ));
        } else {
            output::success(&msg);
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
            "lpm store gc".bold(),
            "lpm install".bold()
        );
    }

    Ok(())
}

fn list_store_verify_entries(store: &PackageStore) -> Result<Vec<(String, String)>, LpmError> {
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

        packages.push((name, version));
    }

    packages.sort();
    Ok(packages)
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

/// List all packages currently in the global store.
fn run_list(store: &PackageStore, json_output: bool) -> Result<(), LpmError> {
    let packages = store.list_packages()?;

    if json_output {
        let entries: Vec<_> = packages
            .iter()
            .map(|(name, ver)| serde_json::json!({"name": name, "version": ver}))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "count": entries.len(),
                "packages": entries,
            }))
            .unwrap()
        );
    } else if packages.is_empty() {
        output::info("Store is empty");
    } else {
        println!("  {} packages in store:", packages.len().to_string().bold());
        for (name, version) in &packages {
            println!("    {}@{}", name, version.dimmed());
        }
        println!();
    }

    Ok(())
}

/// Parse a human-readable duration string like "30d" or "24h" into a `Duration`.
///
/// Supported units:
/// - `d` — days (e.g., "7d" = 7 days)
/// - `h` — hours (e.g., "24h" = 24 hours)
fn parse_duration(s: &str) -> Result<std::time::Duration, LpmError> {
    let (num_str, unit) = if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 'd')
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 'h')
    } else {
        return Err(LpmError::Script(format!(
            "invalid duration: {s}. Use '7d' or '24h'"
        )));
    };
    let num: u64 = num_str
        .parse()
        .map_err(|_| LpmError::Script(format!("invalid number in duration: {s}")))?;
    if num == 0 {
        return Err(LpmError::Script(format!("duration must be positive: {s}")));
    }
    let multiplier: u64 = match unit {
        'd' => 86400,
        'h' => 3600,
        _ => unreachable!(),
    };
    let secs = num
        .checked_mul(multiplier)
        .ok_or_else(|| LpmError::Script(format!("duration overflow: {s} is too large")))?;
    Ok(std::time::Duration::from_secs(secs))
}

/// Garbage collect: remove packages not referenced by any lockfile in the current project.
///
/// # Warning
/// This only considers packages referenced by the lockfile in the CURRENT directory.
/// Packages used by OTHER projects are NOT considered and may be incorrectly removed.
/// To safely GC across all projects, run `lpm store gc` from each project directory first,
/// or use `--dry-run` to preview what would be removed.
///
/// With `--dry-run`, shows what would be removed without deleting.
/// With `--older-than`, only removes packages whose mtime exceeds the threshold.
/// Without a lockfile, requires `--force` to proceed (prevents accidental deletion of
/// packages used by other projects).
fn run_gc(
    store: &PackageStore,
    dry_run: bool,
    older_than: Option<&str>,
    force: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    // Parse older_than duration if provided
    let max_age = older_than.map(parse_duration).transpose()?;

    // Collect referenced packages from the current directory's lockfile
    let cwd = std::env::current_dir().map_err(LpmError::Io)?;
    let lockfile_path = cwd.join("lpm.lock");

    let referenced: HashSet<String> = if lockfile_path.exists() {
        match lpm_lockfile::Lockfile::read_fast(&lockfile_path) {
            Ok(lockfile) => lockfile
                .packages
                .iter()
                .map(|p| format!("{}@{}", p.name, p.version))
                .collect(),
            Err(e) => {
                tracing::debug!("Failed to read lockfile for GC: {e}");
                HashSet::new()
            }
        }
    } else {
        // No lockfile means no references — GC will remove everything
        if !force && !dry_run {
            output::warn("No lpm.lock found in current directory.");
            output::warn("GC will treat ALL stored packages as unreferenced.");
            output::warn("Run from a project directory with lpm.lock, or use --dry-run first.");
            return Err(LpmError::Script(
                "no lockfile found — refusing to GC without --force".into(),
            ));
        }
        if !json_output {
            output::warn(
                "No lpm.lock found in current directory. All packages will be considered unreferenced.",
            );
        }
        HashSet::new()
    };

    if dry_run {
        let preview = store.gc_preview(&referenced, max_age.as_ref())?;

        if json_output {
            let entries: Vec<_> = preview
                .would_remove
                .iter()
                .map(|(name, size)| serde_json::json!({"name": name, "bytes": size}))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "dry_run": true,
                    "would_remove": preview.would_remove.len(),
                    "would_keep": preview.would_keep,
                    "would_free_bytes": preview.would_free_bytes,
                    "would_free": lpm_common::format_bytes(preview.would_free_bytes),
                    "packages": entries,
                }))
                .unwrap()
            );
        } else if preview.would_remove.is_empty() {
            output::success(&format!(
                "Nothing to clean ({} packages in use)",
                preview.would_keep
            ));
        } else {
            println!(
                "  Would remove {} packages (free {}):",
                preview.would_remove.len().to_string().bold(),
                lpm_common::format_bytes(preview.would_free_bytes).bold(),
            );
            for (name, size) in &preview.would_remove {
                println!("    {} {}", name, lpm_common::format_bytes(*size).dimmed());
            }
            println!();
            println!(
                "  Run {} to actually remove these packages.",
                "lpm store gc".bold()
            );
        }
    } else {
        let result = store.gc(&referenced, max_age.as_ref())?;

        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "removed": result.removed,
                    "kept": result.kept,
                    "freed_bytes": result.freed_bytes,
                    "freed": lpm_common::format_bytes(result.freed_bytes),
                }))
                .unwrap()
            );
        } else if result.removed == 0 {
            output::success(&format!(
                "Nothing to clean ({} packages in use)",
                result.kept
            ));
        } else {
            output::success(&format!(
                "Removed {} unused packages (freed {}), {} kept",
                result.removed,
                lpm_common::format_bytes(result.freed_bytes),
                result.kept,
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_valid_days() {
        let d = parse_duration("7d").unwrap();
        assert_eq!(d, std::time::Duration::from_secs(604800));
    }

    #[test]
    fn parse_duration_valid_hours() {
        let d = parse_duration("24h").unwrap();
        assert_eq!(d, std::time::Duration::from_secs(86400));
    }

    #[test]
    fn parse_duration_one_day() {
        let d = parse_duration("1d").unwrap();
        assert_eq!(d, std::time::Duration::from_secs(86400));
    }

    #[test]
    fn parse_duration_one_hour() {
        let d = parse_duration("1h").unwrap();
        assert_eq!(d, std::time::Duration::from_secs(3600));
    }

    #[test]
    fn parse_duration_zero_rejected() {
        assert!(parse_duration("0d").is_err());
    }

    #[test]
    fn parse_duration_empty_rejected() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn parse_duration_no_unit_rejected() {
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn parse_duration_unsupported_unit_rejected() {
        assert!(parse_duration("30m").is_err());
    }

    #[test]
    fn parse_duration_negative_rejected() {
        assert!(parse_duration("-5d").is_err());
    }

    #[test]
    fn parse_duration_overflow_rejected() {
        assert!(parse_duration("999999999999999999d").is_err());
    }

    // ─── Store verify ────────────────────────────────────────────────

    fn make_test_analysis() -> lpm_security::behavioral::PackageAnalysis {
        lpm_security::behavioral::PackageAnalysis {
            version: 1,
            analyzed_at: "2026-01-01T00:00:00Z".to_string(),
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
        b.analyzed_at = "2026-06-15T12:00:00Z".to_string();
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
        run_verify(&store, true, false, true).unwrap();
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
        run_verify(&store, true, true, true).unwrap();
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
        run_verify(&store, true, false, true).unwrap();
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
        run_verify(&store, true, true, true).unwrap();
        assert!(
            pkg_dir.join(".lpm-security.json").exists(),
            "verify with --fix must create .lpm-security.json"
        );
    }
}
