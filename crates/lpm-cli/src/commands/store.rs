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
                run_gc(&root, &store, dry_run, older_than, force, json_output)
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

/// Garbage collect: remove packages not referenced by the current project
/// OR by any globally-installed package.
///
/// The referenced set is the UNION of:
///
/// 1. **Current-project refs** — every `name@version` in the cwd's
///    `lpm.lock` (if present). Unchanged from pre-Phase-37 semantics.
///
/// 2. **Global-install refs** — every `name@version` in every globally-
///    installed package's lockfile under `~/.lpm/global/installs/*/lpm.lock`.
///    Added in Phase 37 M3.5. Without this, running `lpm store gc` from a
///    project that doesn't use eslint would evict eslint's store entries
///    even though `lpm install -g eslint` depends on them, breaking the
///    global tool on next launch.
///
/// Packages used by OTHER projects on the host are still not considered
/// (pre-Phase-37 limitation): to safely GC across projects, run from each
/// one first, or use `--dry-run` to preview.
///
/// With `--dry-run`, shows what would be removed without deleting.
/// With `--older-than`, only removes packages whose mtime exceeds the threshold.
/// Without a lockfile AND without any global installs, requires `--force`
/// to proceed (prevents accidental deletion of packages used by other
/// projects on the host).
///
/// `gc` also runs a global tombstone sweep (M3.5) as part of its work,
/// so `lpm store gc` is the user-facing "clean everything" command for
/// both content-addressable store and deferred-delete global installs.
fn run_gc(
    root: &LpmRoot,
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

    let mut referenced: HashSet<String> = HashSet::new();
    let mut has_cwd_lockfile = false;

    if lockfile_path.exists() {
        has_cwd_lockfile = true;
        match lpm_lockfile::Lockfile::read_fast(&lockfile_path) {
            Ok(lockfile) => {
                for p in &lockfile.packages {
                    referenced.insert(format!("{}@{}", p.name, p.version));
                }
            }
            Err(e) => tracing::debug!("Failed to read cwd lockfile for GC: {e}"),
        }
    }

    // Union global-install refs. Each globally-installed package has its
    // own `lpm.lock` inside its install root (produced by the normal
    // install pipeline M3.2 routed through for global installs). We read
    // each one and union the entries into `referenced` — those are the
    // store keys that global tools depend on.
    let global_refs_before = referenced.len();
    let (global_package_count, unreadable_lockfiles) =
        collect_global_install_refs(root, &mut referenced);
    let global_refs_added = referenced.len() - global_refs_before;
    for (pkg, err) in &unreadable_lockfiles {
        tracing::debug!("global install '{pkg}': lockfile unreadable for GC: {err}");
    }

    if !has_cwd_lockfile && global_package_count == 0 {
        // No cwd lockfile AND no globally-installed packages — the
        // referenced set is genuinely empty. Same guard as before: the
        // user almost certainly doesn't want to wipe the store.
        if !force && !dry_run {
            output::warn("No lpm.lock found in current directory.");
            output::warn("No globally-installed packages either.");
            output::warn("GC would treat ALL stored packages as unreferenced.");
            output::warn("Run from a project directory with lpm.lock, or use --dry-run first.");
            return Err(LpmError::Script(
                "no lockfile found and no globally-installed packages — refusing to GC without --force"
                    .into(),
            ));
        }
        if !json_output {
            output::warn(
                "No lpm.lock found in current directory and no globally-installed packages. \
                 All packages will be considered unreferenced.",
            );
        }
    } else if !has_cwd_lockfile && global_package_count > 0 && !json_output {
        // cwd has no lockfile, but we have globally-installed packages
        // keeping some store entries live. Mention it so the user knows
        // this gc is narrower than "everything in this project" — they
        // may still want to run from a project dir for a fuller sweep.
        output::info(&format!(
            "No lpm.lock in cwd. Keeping {global_refs_added} store entries referenced by \
             {global_package_count} globally-installed package(s); run from a project dir to \
             consider its lockfile too.",
        ));
    }

    if dry_run {
        let preview = store.gc_preview(&referenced, max_age.as_ref())?;
        // Dry-run tombstone preview: count pending tombstones without
        // deleting them. The manifest is the source of truth — reading
        // it here is safe without a lock because we never mutate.
        let tombstone_count = count_pending_tombstones(root);

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
                    "tombstones_pending": tombstone_count,
                }))
                .unwrap()
            );
        } else if preview.would_remove.is_empty() && tombstone_count == 0 {
            output::success(&format!(
                "Nothing to clean ({} packages in use)",
                preview.would_keep
            ));
        } else {
            if !preview.would_remove.is_empty() {
                println!(
                    "  Would remove {} packages (free {}):",
                    preview.would_remove.len().to_string().bold(),
                    lpm_common::format_bytes(preview.would_free_bytes).bold(),
                );
                for (name, size) in &preview.would_remove {
                    println!("    {} {}", name, lpm_common::format_bytes(*size).dimmed());
                }
                println!();
            }
            if tombstone_count > 0 {
                println!(
                    "  Would sweep {} global-install tombstone(s).",
                    tombstone_count.to_string().bold(),
                );
                println!();
            }
            println!(
                "  Run {} to actually remove these packages.",
                "lpm store gc".bold()
            );
        }
    } else {
        let result = store.gc(&referenced, max_age.as_ref())?;

        // Phase 37 M3.5: sweep globally-installed tombstones as part of
        // `store gc`. Blocking acquire of the global tx lock — `store gc`
        // is the user-facing "clean everything" command and it's
        // reasonable to wait briefly for another global command to
        // finish. Failures are non-fatal: `store gc` should still report
        // its content-addressable store cleanup even if the tombstone
        // sweep hits an error.
        let sweep = match lpm_global::sweep_tombstones(root) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("store gc: global tombstone sweep failed: {e}");
                lpm_global::SweepReport::default()
            }
        };

        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "removed": result.removed,
                    "kept": result.kept,
                    "freed_bytes": result.freed_bytes,
                    "freed": lpm_common::format_bytes(result.freed_bytes),
                    "tombstones_swept": sweep.swept.len(),
                    "tombstones_retained": sweep.retained.len(),
                    "tombstone_bytes_freed": sweep.freed_bytes,
                }))
                .unwrap()
            );
        } else {
            if result.removed == 0 {
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
            if !sweep.swept.is_empty() {
                output::success(&format!(
                    "Swept {} global-install tombstone(s) (freed {})",
                    sweep.swept.len(),
                    lpm_common::format_bytes(sweep.freed_bytes),
                ));
            }
            if !sweep.retained.is_empty() {
                output::warn(&format!(
                    "{} tombstone(s) could not be cleaned (files in use?); will retry on next gc",
                    sweep.retained.len(),
                ));
                for failure in &sweep.retained {
                    output::warn(&format!("  {}: {}", failure.relative_path, failure.reason));
                }
            }
        }
    }

    Ok(())
}

/// Read every globally-installed package's `lpm.lock` and union its
/// entries into `referenced`. Returns `(package_count, unreadable_errors)`.
/// `package_count` includes installs whose lockfile could not be read —
/// the caller uses it as "does any global-install scope exist?" signal,
/// not as a precise ref count.
///
/// Missing `global/manifest.toml` returns `(0, vec![])`. Missing per-
/// package lockfiles are degenerate installs (e.g. half-complete old
/// installs predating M3) and produce an "unreadable" entry; GC proceeds
/// without those refs. We don't treat a missing per-install lockfile as
/// fatal — the worst case is re-downloading one package on next install.
fn collect_global_install_refs(
    root: &LpmRoot,
    referenced: &mut HashSet<String>,
) -> (usize, Vec<(String, String)>) {
    let manifest_path = root.global_manifest();
    if !manifest_path.exists() {
        return (0, Vec::new());
    }
    // Read with the no-lock read_for — we are not mutating. Store gc
    // holds the store_gc_lock, which is disjoint from the global tx
    // lock; any concurrent global tx could rewrite the manifest from
    // under us, but since we're only building a LIVE set (a larger set
    // means conservative / keep-more, not drop-more), a momentary race
    // can at worst cause us to keep a package that's about to become
    // unreferenced — safe.
    let manifest = match lpm_global::read_for(root) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                "store gc: could not read global manifest ({e}); skipping global ref union"
            );
            return (0, Vec::new());
        }
    };

    let package_count = manifest.packages.len();
    let mut unreadable: Vec<(String, String)> = Vec::new();
    for (name, entry) in &manifest.packages {
        let install_root = root.global_root().join(&entry.root);
        let lockfile_path = install_root.join("lpm.lock");
        match lpm_lockfile::Lockfile::read_fast(&lockfile_path) {
            Ok(lockfile) => {
                for p in &lockfile.packages {
                    referenced.insert(format!("{}@{}", p.name, p.version));
                }
            }
            Err(e) => unreadable.push((name.clone(), e.to_string())),
        }
    }
    (package_count, unreadable)
}

/// Count pending tombstones without acquiring the tx lock. Used only
/// for `store gc --dry-run` preview — races are cosmetic (the actual
/// non-dry-run sweep takes the lock and is authoritative).
fn count_pending_tombstones(root: &LpmRoot) -> usize {
    if !root.global_manifest().exists() {
        return 0;
    }
    lpm_global::read_for(root)
        .map(|m| m.tombstones.len())
        .unwrap_or(0)
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

    // ─── Phase 37 M3.5: global-install reference union ───────────────

    /// Helper: seed a globally-installed package at `~/.lpm/global/installs/<rel>/`
    /// with a valid `lpm.lock` listing `deps` as (name, version) pairs.
    /// Also inserts the corresponding `[packages]` row in the global manifest.
    fn seed_global_install(
        root: &LpmRoot,
        pkg_name: &str,
        pkg_version: &str,
        rel: &str,
        deps: &[(&str, &str)],
    ) {
        let install_root = root.global_root().join(rel);
        std::fs::create_dir_all(&install_root).unwrap();

        let mut lockfile = lpm_lockfile::Lockfile::new();
        // Include the package itself so it appears as a live ref too.
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: pkg_name.into(),
            version: pkg_version.into(),
            source: None,
            integrity: None,
            dependencies: Vec::new(),
        });
        for (name, version) in deps {
            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: (*name).into(),
                version: (*version).into(),
                source: None,
                integrity: None,
                dependencies: Vec::new(),
            });
        }
        lockfile
            .write_to_file(&install_root.join("lpm.lock"))
            .unwrap();

        // Upsert the package row in the manifest.
        let mut manifest = lpm_global::read_for(root).unwrap_or_default();
        manifest.packages.insert(
            pkg_name.into(),
            lpm_global::PackageEntry {
                saved_spec: format!("^{pkg_version}"),
                resolved: pkg_version.into(),
                integrity: "sha512-test".into(),
                source: lpm_global::PackageSource::UpstreamNpm,
                installed_at: chrono::Utc::now(),
                root: rel.into(),
                commands: vec![pkg_name.into()],
            },
        );
        lpm_global::write_for(root, &manifest).unwrap();
    }

    /// The core behaviour: a package present ONLY in a globally-installed
    /// package's lockfile must be unioned into the live set, so `store gc`
    /// won't evict it.
    #[test]
    fn collect_global_install_refs_unions_per_install_lockfiles() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed_global_install(
            &root,
            "eslint",
            "9.24.0",
            "installs/eslint@9.24.0",
            &[("@eslint/core", "0.15.1"), ("chalk", "5.3.0")],
        );
        seed_global_install(
            &root,
            "prettier",
            "3.8.3",
            "installs/prettier@3.8.3",
            &[("chalk", "5.3.0")], // shared transitive with eslint — set handles dup
        );

        let mut referenced: HashSet<String> = HashSet::new();
        let (count, unreadable) = collect_global_install_refs(&root, &mut referenced);

        assert_eq!(count, 2, "both globally-installed packages counted");
        assert!(unreadable.is_empty(), "both lockfiles readable");

        // Every live ref must be present. chalk appears in both lockfiles
        // but HashSet dedups — we only care that it's PRESENT.
        assert!(referenced.contains("eslint@9.24.0"));
        assert!(referenced.contains("prettier@3.8.3"));
        assert!(referenced.contains("@eslint/core@0.15.1"));
        assert!(referenced.contains("chalk@5.3.0"));
    }

    /// A globally-installed package whose `lpm.lock` is missing or
    /// corrupt must not fail the GC. It's reported in the unreadable
    /// list (caller logs it) and the install is counted so the "no
    /// global installs either" guard rail doesn't fire and wipe the
    /// store.
    #[test]
    fn collect_global_install_refs_tolerates_missing_lockfile() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());

        // Seed the manifest row but DON'T write the lockfile.
        let mut manifest = lpm_global::GlobalManifest::default();
        manifest.packages.insert(
            "orphan".into(),
            lpm_global::PackageEntry {
                saved_spec: "^1".into(),
                resolved: "1.0.0".into(),
                integrity: "sha512-x".into(),
                source: lpm_global::PackageSource::UpstreamNpm,
                installed_at: chrono::Utc::now(),
                root: "installs/orphan@1.0.0".into(),
                commands: vec![],
            },
        );
        lpm_global::write_for(&root, &manifest).unwrap();
        std::fs::create_dir_all(root.global_root().join("installs/orphan@1.0.0")).unwrap();
        // No lpm.lock in the install root.

        let mut referenced: HashSet<String> = HashSet::new();
        let (count, unreadable) = collect_global_install_refs(&root, &mut referenced);

        assert_eq!(count, 1, "orphan still counts toward global install count");
        assert_eq!(unreadable.len(), 1);
        assert_eq!(unreadable[0].0, "orphan");
        // No refs added — the lockfile was missing.
        assert!(referenced.is_empty());
    }

    /// No global manifest on disk (fresh machine, no `lpm install -g`
    /// ever run) must be indistinguishable from "zero globally-installed
    /// packages" so the existing GC guard rail (refuse without --force)
    /// still fires as before.
    #[test]
    fn collect_global_install_refs_returns_zero_when_no_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        // No manifest seeded.

        let mut referenced: HashSet<String> = HashSet::new();
        let (count, unreadable) = collect_global_install_refs(&root, &mut referenced);

        assert_eq!(count, 0);
        assert!(unreadable.is_empty());
        assert!(referenced.is_empty());
    }

    #[test]
    fn count_pending_tombstones_returns_len_when_manifest_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let manifest = lpm_global::GlobalManifest {
            tombstones: vec![
                "installs/a@1.0.0".into(),
                "installs/b@2.0.0".into(),
                "installs/c@3.0.0".into(),
            ],
            ..lpm_global::GlobalManifest::default()
        };
        lpm_global::write_for(&root, &manifest).unwrap();

        assert_eq!(count_pending_tombstones(&root), 3);
    }

    #[test]
    fn count_pending_tombstones_returns_zero_when_no_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        assert_eq!(count_pending_tombstones(&root), 0);
    }
}
