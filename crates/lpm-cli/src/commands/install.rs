use crate::output;
use indicatif::{ProgressBar, ProgressStyle}; // kept for concurrent download progress bar
use lpm_common::LpmError;
use lpm_linker::LinkTarget;
use lpm_registry::RegistryClient;
use lpm_resolver::{ResolvedPackage, check_unmet_peers, resolve_dependencies_with_overrides};
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Maximum number of concurrent tarball downloads.
const MAX_CONCURRENT_DOWNLOADS: usize = 16;

/// Lightweight representation of a resolved package for the install pipeline.
/// Used both for fresh resolution results and lockfile-restored packages.
#[derive(Debug, Clone)]
struct InstallPackage {
    name: String,
    version: String,
    /// Source registry for lockfile
    source: String,
    /// Dependencies: (dep_name, dep_version)
    dependencies: Vec<(String, String)>,
    /// Whether this is a direct dependency of the root project
    is_direct: bool,
    /// Whether this is an LPM package (for tarball fetching)
    is_lpm: bool,
    /// SRI integrity hash for verification (e.g. "sha512-...")
    integrity: Option<String>,
    /// Tarball URL from resolution — avoids re-fetching metadata during download.
    tarball_url: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_with_options(
    client: &RegistryClient,
    project_dir: &Path,
    json_output: bool,
    offline: bool,
    force: bool,
    allow_new: bool,
    linker_override: Option<&str>,
    no_skills: bool,
    no_editor_setup: bool,
    no_security_summary: bool,
    auto_build: bool,
) -> Result<(), LpmError> {
    if !json_output {
        output::print_header();
    }

    let start = Instant::now();

    // Step 1: Read package.json
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "no package.json found in current directory".to_string(),
        ));
    }

    let pkg = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;

    // Fast-exit: if package.json + lockfile haven't changed and node_modules
    // is intact, skip the entire install pipeline. Two stats + one read + one
    // SHA-256 hash ≈ 1-2ms vs 82ms for a full warm install.
    // --force bypasses this check to force a full re-install.
    if !force && !offline && is_install_up_to_date(project_dir) {
        let elapsed = start.elapsed();
        if json_output {
            let json = serde_json::json!({
                "success": true,
                "up_to_date": true,
                "duration_ms": elapsed.as_millis() as u64,
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            // Header already printed at function entry (line 49-51)
            output::success("up to date");
        }
        return Ok(());
    }

    let pkg_name = pkg.name.as_deref().unwrap_or("(unnamed)");
    if !json_output {
        output::info(&format!("Installing dependencies for {}", pkg_name.bold()));
    }

    let mut deps = pkg.dependencies.clone();

    // Resolve workspace:* and catalog: protocols before anything else (lockfile fast
    // path, resolver).  This ensures deps HashMap contains real semver ranges.
    //
    // Catalog resolution must use the workspace ROOT catalogs when inside a workspace,
    // because workspace members define `"catalog:"` references that point to
    // centralized version definitions in the root package.json.
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .ok()
        .flatten();

    if let Some(ref ws) = workspace {
        // workspace:* protocol
        let resolved = lpm_workspace::resolve_workspace_protocol(&mut deps, ws)
            .map_err(LpmError::Workspace)?;
        if !resolved.is_empty() && !json_output {
            for (name, _original, resolved_ver) in &resolved {
                tracing::debug!("workspace protocol: {name} → {resolved_ver}");
            }
        }

        // catalog: protocol — resolve from workspace root catalogs
        if !ws.root_package.catalogs.is_empty() {
            match lpm_workspace::resolve_catalog_protocol(&mut deps, &ws.root_package.catalogs) {
                Ok(resolved) => {
                    if !resolved.is_empty() && !json_output {
                        for (name, _orig, ver) in &resolved {
                            tracing::debug!("catalog: {name} → {ver}");
                        }
                    }
                }
                Err(e) => {
                    return Err(LpmError::Registry(format!(
                        "catalog resolution failed: {e}"
                    )));
                }
            }
        }
    } else if !pkg.catalogs.is_empty() {
        // Standalone project (no workspace): use local catalogs
        match lpm_workspace::resolve_catalog_protocol(&mut deps, &pkg.catalogs) {
            Ok(resolved) => {
                if !resolved.is_empty() && !json_output {
                    for (name, _orig, ver) in &resolved {
                        tracing::debug!("catalog: {name} → {ver}");
                    }
                }
            }
            Err(e) => {
                return Err(LpmError::Registry(format!(
                    "catalog resolution failed: {e}"
                )));
            }
        }
    }

    if deps.is_empty() {
        if !json_output {
            output::success("No dependencies to install");
        }
        return Ok(());
    }

    // Collect overrides from package.json (npm overrides + yarn resolutions)
    let mut overrides = pkg.overrides.clone();
    for (k, v) in &pkg.resolutions {
        overrides.entry(k.clone()).or_insert_with(|| v.clone());
    }

    // Determine linker mode early: CLI flag > package.json config > default (isolated)
    let linker_mode = linker_override
        .or_else(|| pkg.lpm.as_ref().and_then(|l| l.linker.as_deref()))
        .map(|s| match s {
            "hoisted" => lpm_linker::LinkerMode::Hoisted,
            _ => lpm_linker::LinkerMode::Isolated,
        })
        .unwrap_or(lpm_linker::LinkerMode::Isolated);

    // Step 2: Try lockfile fast path, else resolve
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let arc_client = Arc::new(client.clone_with_config());

    // Offline mode: require lockfile, no network
    if offline {
        let locked = try_lockfile_fast_path(&lockfile_path, &deps).ok_or_else(|| {
            LpmError::Registry(
                "--offline requires a lockfile. Run `lpm-rs install` online first.".into(),
            )
        })?;
        if !json_output {
            output::info(&format!(
                "Offline: using lockfile ({} packages)",
                locked.len().to_string().bold()
            ));
        }

        // Verify all packages are in the global store
        let store = PackageStore::default_location()?;
        let mut missing = Vec::new();
        for p in &locked {
            if !store.has_package(&p.name, &p.version) {
                missing.push(format!("{}@{}", p.name, p.version));
            }
        }
        if !missing.is_empty() {
            return Err(LpmError::Registry(format!(
                "--offline: {} package(s) not in global store: {}",
                missing.len(),
                missing[..missing.len().min(5)].join(", ")
            )));
        }

        // Go directly to link step (skip resolution and download)
        return run_link_and_finish(
            client,
            project_dir,
            &deps,
            &pkg,
            locked,
            0,
            0,
            true,
            json_output,
            start,
            linker_mode,
            force,
        )
        .await;
    }

    // --force skips lockfile fast path to force fresh resolution from registry.
    let lockfile_result = if force {
        None
    } else {
        try_lockfile_fast_path(&lockfile_path, &deps)
    };
    let (mut packages, resolve_ms, used_lockfile) = match lockfile_result {
        Some(locked_packages) => {
            if !json_output {
                output::info(&format!(
                    "Using lockfile ({} packages)",
                    locked_packages.len().to_string().bold()
                ));
            }
            (locked_packages, 0u128, true)
        }
        None => {
            let resolve_start = Instant::now();
            let spinner = make_spinner("Resolving dependency tree...");

            // Batch prefetch: warm the metadata cache for all root deps in one request.
            // This turns 70+ sequential HTTP requests into 1-3 batch requests.
            // Skip if all root deps are already in the metadata cache (warm install).
            let dep_names: Vec<String> = deps.keys().cloned().collect();
            let cache_has_all = dep_names.iter().all(|name| {
                let cache_key = if name.starts_with("@lpm.dev/") {
                    format!("lpm:{name}")
                } else {
                    format!("npm:{name}")
                };
                // Check if metadata cache file exists and is fresh
                let cache_dir =
                    dirs::home_dir().map(|h| h.join(".lpm").join("cache").join("metadata"));
                cache_dir
                    .and_then(|dir| {
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(cache_key.as_bytes());
                        let hash = format!("{:x}", hasher.finalize());
                        let path = dir.join(&hash[..16]);
                        let modified = path.metadata().ok()?.modified().ok()?;
                        let age = std::time::SystemTime::now().duration_since(modified).ok()?;
                        Some(age < std::time::Duration::from_secs(300))
                    })
                    .unwrap_or(false)
            });

            if !dep_names.is_empty() && !cache_has_all {
                // Single deep batch: server resolves transitive deps recursively
                // (up to 3 levels), returning ALL metadata in one round-trip.
                // This replaces the 3 sequential wave calls.
                match arc_client.batch_metadata_deep(&dep_names).await {
                    Ok(batch) => {
                        tracing::debug!(
                            "batch prefetch (deep): {} total packages cached",
                            batch.len()
                        );
                    }
                    Err(e) => {
                        // Non-fatal: resolver will fetch individually as fallback,
                        // but this is a significant performance regression (1 request → 50+).
                        // Warn so users/CI can diagnose slow installs.
                        tracing::warn!(
                            "batch prefetch failed, falling back to sequential resolution (slower): {e}"
                        );
                        if !json_output {
                            output::warn(
                                "Batch prefetch failed — falling back to sequential resolution (this will be slower).",
                            );
                        }
                    }
                }
            }

            let resolve_result = resolve_dependencies_with_overrides(
                arc_client.clone(),
                deps.clone(),
                overrides.clone(),
            )
            .await
            .map_err(|e| LpmError::Registry(format!("resolution failed: {e}")))?;

            let ms = resolve_start.elapsed().as_millis();
            spinner.stop(format!("Resolved in {ms}ms"));

            // Post-resolution peer dependency check: warn about unmet peers
            // using each package's actual selected version (not a union).
            let peer_warnings = check_unmet_peers(&resolve_result.packages, &resolve_result.cache);
            if !peer_warnings.is_empty() && !json_output {
                for w in &peer_warnings {
                    output::warn(&format!("peer dep: {w}"));
                }
            }

            let packages = resolved_to_install_packages(&resolve_result.packages, &deps);

            if !json_output {
                output::info(&format!(
                    "Resolved {} packages ({}ms)",
                    packages.len().to_string().bold(),
                    ms
                ));
            }
            (packages, ms, false)
        }
    };

    // Step 3: Download & store (parallel)
    let fetch_start = Instant::now();
    let store = PackageStore::default_location()?;

    let mut to_download = Vec::new();
    let mut cached = 0usize;

    for p in &packages {
        // --force: re-download everything to verify integrity against registry,
        // even if the store already has it. The store's extract-to-temp + atomic
        // rename handles the case where the existing entry is valid.
        if !force && store.has_package(&p.name, &p.version) {
            cached += 1;
        } else {
            to_download.push(p.clone());
        }
    }

    // Enforce minimumReleaseAge: block recently published packages unless --allow-new.
    // Only checked during fresh resolution (not lockfile fast path) because metadata
    // was already fetched and cached by the resolver — re-fetching hits the 5-min TTL cache.
    if !allow_new && !used_lockfile {
        let policy =
            lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));
        if policy.minimum_release_age_secs > 0 {
            let mut too_new = Vec::new();
            for p in &packages {
                // Look up the publish timestamp from the metadata cache.
                // During fresh resolution the resolver already fetched all metadata,
                // so these calls hit the local cache (no extra network round-trips).
                let publish_time = if p.is_lpm {
                    lpm_common::PackageName::parse(&p.name)
                        .ok()
                        .and_then(|pkg_name| {
                            // This will hit the TTL cache (< 5 min since resolution)
                            tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current()
                                    .block_on(arc_client.get_package_metadata(&pkg_name))
                            })
                            .ok()
                        })
                        .and_then(|meta| meta.time.get(&p.version).cloned())
                } else {
                    tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current()
                            .block_on(arc_client.get_npm_package_metadata(&p.name))
                    })
                    .ok()
                    .and_then(|meta| meta.time.get(&p.version).cloned())
                };

                if let Some(warning) = policy.check_release_age(publish_time.as_deref()) {
                    let remaining = warning.minimum.saturating_sub(warning.age_secs);
                    let hours = remaining / 3600;
                    let minutes = (remaining % 3600) / 60;
                    too_new.push((p.name.clone(), p.version.clone(), hours, minutes));
                }
            }

            if !too_new.is_empty() {
                if !json_output {
                    output::warn(&format!(
                        "{} package(s) blocked by minimumReleaseAge ({}s):",
                        too_new.len(),
                        policy.minimum_release_age_secs,
                    ));
                    for (name, version, hours, minutes) in &too_new {
                        eprintln!(
                            "    {}@{} — {}h {}m remaining",
                            name, version, hours, minutes
                        );
                    }
                    eprintln!(
                        "  Use {} to install anyway, or add {} to package.json to disable.",
                        "--allow-new".bold(),
                        "\"lpm\": { \"minimumReleaseAge\": 0 }".dimmed(),
                    );
                }
                return Err(LpmError::Registry(format!(
                    "{} package(s) published too recently (minimumReleaseAge={}s). Use --allow-new to override.",
                    too_new.len(),
                    policy.minimum_release_age_secs,
                )));
            }
        }
    }

    let downloaded = to_download.len();
    if !to_download.is_empty() {
        let overall = ProgressBar::new(to_download.len() as u64);
        overall.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} Downloading [{bar:30.cyan/dim}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("━╸─"),
        );
        overall.enable_steady_tick(std::time::Duration::from_millis(80));

        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS));
        let mut handles = Vec::new();

        for p in to_download {
            let sem = semaphore.clone();
            let client = arc_client.clone();
            let store_ref = store.clone();
            let overall = overall.clone();

            handles.push(tokio::spawn(async move {
                let _permit = sem
                    .acquire()
                    .await
                    .map_err(|_| LpmError::Registry("download semaphore closed".into()))?;

                overall.set_message(format!("{}@{}", p.name, p.version));

                // Download tarball to temp file (bounded-memory spool pipeline).
                // Hash is computed during download — no second pass needed.
                // On 404, invalidate stale metadata cache so the next `lpm install`
                // re-resolves with fresh metadata.
                let downloaded = match fetch_tarball_to_file(
                    &client,
                    &p.name,
                    &p.version,
                    p.is_lpm,
                    p.tarball_url.as_deref(),
                )
                .await
                {
                    Ok(result) => result,
                    Err(LpmError::NotFound(_)) => {
                        // Invalidate stale metadata cache
                        client.invalidate_metadata_cache(&p.name);
                        let lock_path = std::path::Path::new("lpm.lock");
                        if lock_path.exists() {
                            let _ = std::fs::remove_file(lock_path);
                        }
                        let lockb_path = std::path::Path::new("lpm.lockb");
                        if lockb_path.exists() {
                            let _ = std::fs::remove_file(lockb_path);
                        }
                        return Err(LpmError::NotFound(format!(
                            "{}@{} tarball not found (possibly unpublished). \
                                 Cache cleared — run `lpm install` again to re-resolve.",
                            p.name, p.version
                        )));
                    }
                    Err(e) => return Err(e),
                };

                let computed_sri = downloaded.sri.clone();

                // Verify integrity before storing — prevents tampered tarballs
                // from entering the global store. The SHA-512 SRI hash was computed
                // during download (streaming), so most verifications are a string
                // comparison. For non-sha512 algorithms (sha256), we stream-verify
                // from the temp file in 64KB chunks — never buffers the tarball in memory.
                if let Some(ref integrity) = p.integrity {
                    if computed_sri != *integrity {
                        // Different algorithm or hash mismatch — verify from file (bounded-memory)
                        if let Err(e) =
                            lpm_extractor::verify_integrity_file(downloaded.file.path(), integrity)
                        {
                            return Err(LpmError::Registry(format!(
                                "integrity verification failed for {}@{}: {e}",
                                p.name, p.version
                            )));
                        }
                    }
                } else {
                    tracing::warn!(
                        "no integrity hash for {}@{} — skipping verification",
                        p.name,
                        p.version
                    );
                }

                // Extract from temp file — bounded memory, tarball never in heap
                store_ref.store_package_from_file(
                    &p.name,
                    &p.version,
                    downloaded.file.path(),
                    &computed_sri,
                )?;

                overall.inc(1);
                // Return (name, version, computed_sri) so integrity can be persisted in lockfile
                Ok::<(String, String, String), LpmError>((
                    p.name.clone(),
                    p.version.clone(),
                    computed_sri,
                ))
            }));
        }

        // Collect computed integrity hashes from downloads
        let mut integrity_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for handle in handles {
            let (name, version, sri) = handle
                .await
                .map_err(|e| LpmError::Registry(format!("download task panicked: {e}")))??;
            integrity_map.insert(format!("{name}@{version}"), sri);
        }

        // Update packages with computed integrity hashes (for lockfile persistence)
        for p in &mut packages {
            let key = format!("{}@{}", p.name, p.version);
            if let Some(sri) = integrity_map.get(&key) {
                p.integrity = Some(sri.clone());
            }
        }

        overall.finish_and_clear();
    }

    let fetch_ms = fetch_start.elapsed().as_millis();
    if !json_output {
        if downloaded > 0 {
            output::info(&format!(
                "Downloaded {} packages, {} from cache ({}ms)",
                downloaded.to_string().bold(),
                cached,
                fetch_ms
            ));
        } else {
            output::info(&format!("All {} packages from cache", cached));
        }
    }

    // Step 4: Build link targets
    let link_targets: Vec<LinkTarget> = packages
        .iter()
        .map(|p| LinkTarget {
            name: p.name.clone(),
            version: p.version.clone(),
            store_path: store.package_dir(&p.name, &p.version),
            dependencies: p.dependencies.clone(),
            is_direct: p.is_direct,
        })
        .collect();

    // Step 5: Link into node_modules
    let link_start = Instant::now();
    let spinner = make_spinner("Linking node_modules...");

    let link_result = match linker_mode {
        lpm_linker::LinkerMode::Hoisted => lpm_linker::link_packages_hoisted(
            project_dir,
            &link_targets,
            force,
            pkg.name.as_deref(),
        )?,
        lpm_linker::LinkerMode::Isolated => {
            lpm_linker::link_packages(project_dir, &link_targets, force, pkg.name.as_deref())?
        }
    };

    let link_ms = link_start.elapsed().as_millis();
    spinner.stop(format!("Linked in {link_ms}ms"));

    // Step 6: Lifecycle script security audit + trusted script execution
    let policy = lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));
    // Show build hint for packages with lifecycle scripts (Phase 25: two-phase model)
    // Scripts are NEVER executed during install — use `lpm build` instead.
    if !json_output {
        let all_pkgs: Vec<(String, String)> = packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        crate::commands::build::show_install_build_hint(&store, &all_pkgs, &policy, project_dir);
    }

    // Step 7: LPM-Native Intelligence (Phase 5)
    // Read strictness from package.json "lpm" config
    let strict_deps = pkg
        .lpm
        .as_ref()
        .and_then(|l| l.strict_deps.as_deref())
        .unwrap_or("warn");

    if strict_deps != "loose" && !json_output {
        let installed_names: std::collections::HashSet<String> =
            packages.iter().map(|p| p.name.clone()).collect();

        // Phantom dependency detection
        let phantom_result =
            crate::intelligence::detect_phantom_deps(project_dir, &deps, &installed_names);

        if !phantom_result.phantom_imports.is_empty() {
            let icon = if strict_deps == "strict" {
                "✖"
            } else {
                "⚠"
            };
            println!();
            output::warn(&format!(
                "{}  {} phantom dependency import(s) detected:",
                icon,
                phantom_result.phantom_imports.len()
            ));
            for phantom in phantom_result.phantom_imports.iter().take(5) {
                let rel_file = phantom
                    .file
                    .strip_prefix(project_dir)
                    .unwrap_or(&phantom.file);
                println!(
                    "    {} ({}:{})",
                    phantom.package_name.bold(),
                    rel_file.display().to_string().dimmed(),
                    phantom.line,
                );
                if let Some(via) = &phantom.available_via {
                    println!("      {}", via.dimmed());
                }
                println!(
                    "      Fix: {}",
                    format!("lpm-rs install {}", phantom.package_name).dimmed()
                );
            }
            if phantom_result.phantom_imports.len() > 5 {
                println!(
                    "    ... and {} more",
                    phantom_result.phantom_imports.len() - 5
                );
            }
        }

        // Import verification (only in strict mode)
        if strict_deps == "strict" {
            let verification =
                crate::intelligence::verify_imports(project_dir, &installed_names, &deps);
            if !verification.unresolved.is_empty() {
                println!();
                output::warn(&format!(
                    "✖  {} import(s) will fail at runtime:",
                    verification.unresolved.len()
                ));
                for unresolved in &verification.unresolved {
                    let rel_file = unresolved
                        .file
                        .strip_prefix(project_dir)
                        .unwrap_or(&unresolved.file);
                    println!(
                        "    {}:{} → {}",
                        rel_file.display().to_string().dimmed(),
                        unresolved.line,
                        format!("import \"{}\"", unresolved.specifier).bold(),
                    );
                    println!("      {}", unresolved.suggestion.dimmed());
                }
            }
        }

        // Quality warnings for LPM packages
        let lpm_packages: Vec<(String, String)> = packages
            .iter()
            .filter(|p| p.is_lpm)
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();

        if !lpm_packages.is_empty() {
            let quality_threshold = pkg
                .lpm
                .as_ref()
                .and_then(|l| l.strict_deps.as_deref()) // reuse as quality gate
                .map(|_| 50u32) // warn if below 50 when any strictness is set
                .unwrap_or(30); // default: only warn below 30

            let warnings = crate::intelligence::check_install_quality(
                &lpm_registry::RegistryClient::new()
                    .with_base_url(
                        std::env::var("LPM_REGISTRY_URL")
                            .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
                    )
                    .with_token(
                        crate::auth::get_token(
                            &std::env::var("LPM_REGISTRY_URL")
                                .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
                        )
                        .unwrap_or_default(),
                    ),
                &lpm_packages,
                quality_threshold,
            )
            .await;

            for warning in &warnings {
                let icon = match warning.severity {
                    crate::intelligence::WarningSeverity::Critical => "✖".to_string(),
                    crate::intelligence::WarningSeverity::Warning => "⚠".to_string(),
                    crate::intelligence::WarningSeverity::Info => "ℹ".to_string(),
                };
                println!(
                    "  {icon} {}@{}: {}",
                    warning.package_name, warning.version, warning.message
                );
            }

            // Security summary for ALL packages (client-side analysis + registry enrichment)
            if !no_security_summary {
                let all_packages: Vec<(String, String, bool)> = packages
                    .iter()
                    .map(|p| (p.name.clone(), p.version.clone(), p.is_lpm))
                    .collect();
                crate::security_check::post_install_security_summary(
                    &lpm_registry::RegistryClient::new()
                        .with_base_url(
                            std::env::var("LPM_REGISTRY_URL")
                                .unwrap_or_else(|_| lpm_common::DEFAULT_REGISTRY_URL.to_string()),
                        )
                        .with_token(
                            crate::auth::get_token(
                                &std::env::var("LPM_REGISTRY_URL").unwrap_or_else(|_| {
                                    lpm_common::DEFAULT_REGISTRY_URL.to_string()
                                }),
                            )
                            .unwrap_or_default(),
                        ),
                    &store,
                    &all_packages,
                    json_output,
                    false, // not quiet — show Medium tier too
                )
                .await;
            }
        }
    }

    // Step 8: Auto-install skills for direct LPM packages
    if !json_output && !no_skills {
        let lpm_packages: Vec<String> = packages
            .iter()
            .filter(|p| p.is_lpm && p.is_direct)
            .map(|p| p.name.clone())
            .collect();

        if !lpm_packages.is_empty() {
            install_skills_for_packages(&arc_client, &lpm_packages, project_dir, no_editor_setup)
                .await;
        }
    }

    // Step 9: Write lockfile (only if we resolved fresh)
    if !used_lockfile {
        let mut lockfile = lpm_lockfile::Lockfile::new();
        for p in &packages {
            let dep_strings: Vec<String> = p
                .dependencies
                .iter()
                .map(|(dep_name, dep_ver)| format!("{dep_name}@{dep_ver}"))
                .collect();

            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                source: Some(p.source.clone()),
                integrity: p.integrity.clone(),
                dependencies: dep_strings,
            });
        }

        lockfile
            .write_all(&lockfile_path)
            .map_err(|e| LpmError::Registry(format!("failed to write lockfile: {e}")))?;

        lpm_lockfile::ensure_gitattributes(project_dir)
            .map_err(|e| LpmError::Registry(format!("failed to ensure .gitattributes: {e}")))?;

        if !json_output {
            let lockb_path = lockfile_path.with_extension("lockb");
            let lockb_size = std::fs::metadata(&lockb_path).map(|m| m.len()).unwrap_or(0);
            output::info(&format!(
                "Lockfile  lpm.lock ({} packages) + lpm.lockb ({})",
                lockfile.packages.len(),
                lpm_common::format_bytes(lockb_size),
            ));
        }
    }

    // Step 10: Auto-build trusted packages (after lockfile is written)
    // Triggers when: --auto-build flag, lpm.scripts.autoBuild config, or ALL scripted packages are trusted
    let config_auto_build = read_auto_build_config(project_dir);
    let all_pkgs_for_build: Vec<(String, String)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone()))
        .collect();
    let all_trusted = crate::commands::build::all_scripted_packages_trusted(
        &store,
        &all_pkgs_for_build,
        &policy,
        project_dir,
    );

    if (auto_build || config_auto_build || all_trusted)
        && let Err(e) = crate::commands::build::run(
            project_dir,
            &[],   // no specific packages — build all trusted
            false, // not --all
            false, // not dry-run
            false, // not --rebuild
            None,  // default timeout
            json_output,
            false, // not --unsafe-full-env
            false, // not --deny-all
        )
        .await
        && !json_output
    {
        output::warn(&format!("Auto-build failed: {e}"));
    }

    let elapsed = start.elapsed();

    if json_output {
        let pkg_list: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "source": p.source,
                    "direct": p.is_direct,
                })
            })
            .collect();

        let json = serde_json::json!({
            "success": true,
            "packages": pkg_list,
            "count": packages.len(),
            "downloaded": downloaded,
            "cached": cached,
            "linked": link_result.linked,
            "symlinked": link_result.symlinked,
            "used_lockfile": used_lockfile,
            "duration_ms": elapsed.as_millis() as u64,
            "timing": {
                "resolve_ms": resolve_ms,
                "fetch_ms": fetch_ms,
                "link_ms": link_ms,
                "total_ms": elapsed.as_millis(),
            },
            "warnings": [],
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!();
        output::success(&format!(
            "{} packages installed in {:.1}s",
            packages.len().to_string().bold(),
            elapsed.as_secs_f64()
        ));
        println!(
            "  {} linked, {} symlinked",
            link_result.linked.to_string().dimmed(),
            link_result.symlinked.to_string().dimmed(),
        );
        println!(
            "  resolve: {}ms  fetch: {}ms  link: {}ms",
            resolve_ms.to_string().dimmed(),
            fetch_ms.to_string().dimmed(),
            link_ms.to_string().dimmed(),
        );
        println!();
    }

    // Write install-hash so `lpm dev` knows deps are up to date
    let pkg_json_path = project_dir.join("package.json");
    let lock_path = project_dir.join("lpm.lock");
    if let (Ok(pkg), Ok(lock)) = (
        std::fs::read_to_string(&pkg_json_path),
        std::fs::read_to_string(&lock_path),
    ) {
        let hash = super::dev::compute_install_hash(&pkg, &lock);
        let hash_dir = project_dir.join(".lpm");
        let _ = std::fs::create_dir_all(&hash_dir);
        let _ = std::fs::write(hash_dir.join("install-hash"), &hash);
    }

    Ok(())
}

/// Check whether the install is already up to date by comparing the
/// SHA-256 hash of `package.json + lpm.lock` against `.lpm/install-hash`.
///
/// Also performs a shallow mtime check: if `node_modules` was modified after
/// the hash file was written, we assume something changed externally and
/// return `false` so a full re-link happens.
///
/// Cost: two `stat` calls + two file reads + one SHA-256 hash ≈ 1-2ms.
fn is_install_up_to_date(project_dir: &Path) -> bool {
    let pkg_json = project_dir.join("package.json");
    let lock_path = project_dir.join("lpm.lock");
    let hash_file = project_dir.join(".lpm").join("install-hash");
    let nm = project_dir.join("node_modules");

    // All four artifacts must exist for the fast-exit to apply.
    if !nm.exists() || !hash_file.exists() || !lock_path.exists() || !pkg_json.exists() {
        return false;
    }

    let Ok(pkg_content) = std::fs::read_to_string(&pkg_json) else {
        return false;
    };
    let Ok(lock_content) = std::fs::read_to_string(&lock_path) else {
        return false;
    };
    let Ok(cached_hash) = std::fs::read_to_string(&hash_file) else {
        return false;
    };

    let current_hash = super::dev::compute_install_hash(&pkg_content, &lock_content);
    if cached_hash.trim() != current_hash {
        return false;
    }

    // Shallow verify: if node_modules was modified after the hash was written,
    // something changed externally (user deleted a folder, another tool ran, etc.).
    match (
        std::fs::metadata(&nm).and_then(|m| m.modified()),
        std::fs::metadata(&hash_file).and_then(|m| m.modified()),
    ) {
        (Ok(nm_t), Ok(hash_t)) => nm_t <= hash_t,
        _ => false,
    }
}

/// Try to use the lockfile as a fast path.
///
/// Returns `Some(packages)` if the lockfile exists AND every declared dependency
/// in package.json has a matching entry in the lockfile. Otherwise returns `None`
/// to signal that fresh resolution is needed.
fn try_lockfile_fast_path(
    lockfile_path: &Path,
    deps: &HashMap<String, String>,
) -> Option<Vec<InstallPackage>> {
    if !lpm_lockfile::Lockfile::exists(lockfile_path) {
        return None;
    }

    let lockfile = lpm_lockfile::Lockfile::read_fast(lockfile_path).ok()?;

    // Validate all package sources are safe (HTTPS registries or localhost)
    for lp in &lockfile.packages {
        if let Some(ref source) = lp.source
            && !lpm_lockfile::is_safe_source(source)
        {
            tracing::warn!(
                "package {}@{} has unsafe source URL: {} — skipping lockfile fast path",
                lp.name,
                lp.version,
                source
            );
            return None; // Force re-resolution from trusted registries
        }
    }

    // Verify every declared dep has a lockfile entry
    for dep_name in deps.keys() {
        if lockfile.find_package(dep_name).is_none() {
            tracing::debug!("lockfile miss: {dep_name} not found, re-resolving");
            return None;
        }
    }

    // Build the direct dep set for is_direct marking
    let direct_deps: std::collections::HashSet<&str> = deps.keys().map(|s| s.as_str()).collect();

    // Convert locked packages to InstallPackage
    let packages: Vec<InstallPackage> = lockfile
        .packages
        .iter()
        .map(|lp| {
            let is_lpm = lp.name.starts_with("@lpm.dev/");

            // Parse dependency strings back to (name, version) tuples
            let dependencies: Vec<(String, String)> = lp
                .dependencies
                .iter()
                .filter_map(|dep_str| {
                    // Format: "name@version"
                    dep_str
                        .rfind('@')
                        .map(|at| (dep_str[..at].to_string(), dep_str[at + 1..].to_string()))
                })
                .collect();

            InstallPackage {
                name: lp.name.clone(),
                version: lp.version.clone(),
                source: lp
                    .source
                    .clone()
                    .unwrap_or_else(|| "registry+https://registry.npmjs.org".to_string()),
                dependencies,
                is_direct: direct_deps.contains(lp.name.as_str()),
                is_lpm,
                integrity: lp.integrity.clone(),
                tarball_url: None, // Lockfile doesn't store URLs — fetched on demand
            }
        })
        .collect();

    Some(packages)
}

/// Convert resolver output to InstallPackage list.
fn resolved_to_install_packages(
    resolved: &[ResolvedPackage],
    deps: &HashMap<String, String>,
) -> Vec<InstallPackage> {
    resolved
        .iter()
        .map(|r| {
            let name = r.package.canonical_name();
            let is_lpm = r.package.is_lpm();
            let source = if is_lpm {
                "registry+https://lpm.dev".to_string()
            } else {
                "registry+https://registry.npmjs.org".to_string()
            };

            InstallPackage {
                name: name.clone(),
                version: r.version.to_string(),
                source,
                dependencies: r.dependencies.clone(),
                is_direct: deps.contains_key(&name),
                is_lpm,
                integrity: r.integrity.clone(),
                tarball_url: r.tarball_url.clone(),
            }
        })
        .collect()
}

/// Offline/shared path: link packages from store, write lockfile, print output.
#[allow(clippy::too_many_arguments)]
async fn run_link_and_finish(
    _client: &RegistryClient,
    project_dir: &Path,
    _deps: &HashMap<String, String>,
    pkg: &lpm_workspace::PackageJson,
    packages: Vec<InstallPackage>,
    downloaded: usize,
    cached: usize,
    used_lockfile: bool,
    json_output: bool,
    start: Instant,
    linker_mode: lpm_linker::LinkerMode,
    force: bool,
) -> Result<(), LpmError> {
    let store = PackageStore::default_location()?;

    let link_targets: Vec<LinkTarget> = packages
        .iter()
        .map(|p| LinkTarget {
            name: p.name.clone(),
            version: p.version.clone(),
            store_path: store.package_dir(&p.name, &p.version),
            dependencies: p.dependencies.clone(),
            is_direct: p.is_direct,
        })
        .collect();

    let link_start = Instant::now();
    let link_result = match linker_mode {
        lpm_linker::LinkerMode::Hoisted => lpm_linker::link_packages_hoisted(
            project_dir,
            &link_targets,
            force,
            pkg.name.as_deref(),
        )?,
        lpm_linker::LinkerMode::Isolated => {
            lpm_linker::link_packages(project_dir, &link_targets, force, pkg.name.as_deref())?
        }
    };
    let link_ms = link_start.elapsed().as_millis();

    // Lifecycle script security audit (two-phase model: install never runs scripts).
    // Scripts are NEVER executed during install — use `lpm build` instead.
    // This matches the online install path exactly.
    let policy = lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));
    if !json_output {
        let all_pkgs: Vec<(String, String)> = packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        crate::commands::build::show_install_build_hint(&store, &all_pkgs, &policy, project_dir);
    }

    // Write lockfile if needed
    if !used_lockfile {
        let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
        let mut lockfile = lpm_lockfile::Lockfile::new();
        for p in &packages {
            let dep_strings: Vec<String> = p
                .dependencies
                .iter()
                .map(|(n, v)| format!("{n}@{v}"))
                .collect();
            lockfile.add_package(lpm_lockfile::LockedPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                source: Some(p.source.clone()),
                integrity: p.integrity.clone(),
                dependencies: dep_strings,
            });
        }
        lockfile
            .write_all(&lockfile_path)
            .map_err(|e| LpmError::Registry(format!("failed to write lockfile: {e}")))?;

        lpm_lockfile::ensure_gitattributes(project_dir)
            .map_err(|e| LpmError::Registry(format!("failed to ensure .gitattributes: {e}")))?;

        if !json_output {
            let lockb_path = lockfile_path.with_extension("lockb");
            let lockb_size = std::fs::metadata(&lockb_path).map(|m| m.len()).unwrap_or(0);
            output::info(&format!(
                "Lockfile  lpm.lock ({} packages) + lpm.lockb ({})",
                lockfile.packages.len(),
                lpm_common::format_bytes(lockb_size),
            ));
        }
    }

    let elapsed = start.elapsed();

    if json_output {
        let pkg_list: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "source": p.source,
                    "direct": p.is_direct,
                })
            })
            .collect();

        let json = serde_json::json!({
            "packages": pkg_list,
            "count": packages.len(),
            "downloaded": downloaded,
            "cached": cached,
            "linked": link_result.linked,
            "symlinked": link_result.symlinked,
            "used_lockfile": used_lockfile,
            "offline": true,
            "duration_ms": elapsed.as_millis() as u64,
            "timing": {
                "link_ms": link_ms,
                "total_ms": elapsed.as_millis(),
            },
            "warnings": [],
            "errors": [],
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!();
        output::success(&format!(
            "{} packages installed in {:.1}s",
            packages.len().to_string().bold(),
            elapsed.as_secs_f64()
        ));
        println!(
            "  {} linked, {} symlinked",
            link_result.linked.to_string().dimmed(),
            link_result.symlinked.to_string().dimmed(),
        );
        println!();
    }

    Ok(())
}

/// Fetch tarball + compute SHA-512 hash in one pass.
/// Returns (tarball_bytes, "sha512-{base64}") so the caller can verify
/// integrity without re-hashing the entire buffer.
/// Download a tarball to a temp file on disk (bounded-memory spool pipeline).
///
/// Returns `DownloadedTarball` — the tarball is on disk, never fully in memory.
/// The SRI hash was computed as chunks arrived during download.
async fn fetch_tarball_to_file(
    client: &Arc<RegistryClient>,
    name: &str,
    version: &str,
    is_lpm: bool,
    cached_url: Option<&str>,
) -> Result<lpm_registry::DownloadedTarball, LpmError> {
    // Use the tarball URL from resolution if available — avoids re-fetching
    // metadata just to get the URL (saves one HTTP round-trip per package
    // on the lockfile-miss path).
    let url = if let Some(url) = cached_url {
        url.to_string()
    } else if is_lpm {
        let pkg =
            lpm_common::PackageName::parse(name).map_err(|e| LpmError::Registry(e.to_string()))?;
        let metadata = client.get_package_metadata(&pkg).await?;
        let ver_meta = metadata
            .version(version)
            .ok_or_else(|| LpmError::NotFound(format!("{name}@{version} not found in metadata")))?;
        ver_meta
            .tarball_url()
            .ok_or_else(|| LpmError::NotFound(format!("no tarball URL for {name}@{version}")))?
            .to_string()
    } else {
        let metadata = client.get_npm_package_metadata(name).await?;
        let ver_meta = metadata
            .version(version)
            .ok_or_else(|| LpmError::NotFound(format!("{name}@{version} not found in metadata")))?;
        ver_meta
            .tarball_url()
            .ok_or_else(|| LpmError::NotFound(format!("no tarball URL for {name}@{version}")))?
            .to_string()
    };
    client.download_tarball_to_file(&url).await
}

/// Install specific packages: add them to package.json then run full install.
/// For Swift packages (ecosystem=swift), uses SE-0292 registry mode instead.
///
/// Handles specs like: `express`, `express@^4.0.0`, `@lpm.dev/neo.highlight@1.0.0`
pub async fn run_add_packages(
    client: &RegistryClient,
    project_dir: &Path,
    packages: &[String],
    save_dev: bool,
    json_output: bool,
    allow_new: bool,
    force: bool,
) -> Result<(), LpmError> {
    // First pass: check if any LPM packages are Swift ecosystem
    // Route Swift packages to SE-0292 registry mode
    let mut js_packages = Vec::new();

    for spec in packages {
        let (name, range) = parse_package_spec(spec);

        if name.starts_with("@lpm.dev/") {
            // Fetch metadata to check ecosystem
            let pkg_name = lpm_common::PackageName::parse(&name)?;
            let metadata = client.get_package_metadata(&pkg_name).await?;
            let latest_ver = metadata
                .latest_version_tag()
                .ok_or_else(|| LpmError::NotFound(format!("no versions for {name}")))?;

            // Resolve the user-specified version range against available versions.
            // Falls back to latest when no version is specified.
            let resolved_ver = resolve_version_from_spec(&range, &metadata, latest_ver)?;
            let ver_meta = metadata.version(resolved_ver).ok_or_else(|| {
                LpmError::NotFound(format!("version {resolved_ver} not found for {name}"))
            })?;

            if ver_meta.effective_ecosystem() == "swift" {
                // SE-0292 registry mode
                run_swift_install(
                    project_dir,
                    &pkg_name,
                    resolved_ver,
                    ver_meta,
                    json_output,
                    client.base_url(),
                )
                .await?;
                continue;
            }
        }

        js_packages.push(spec.clone());
    }

    // If all packages were Swift, we're done
    if js_packages.is_empty() {
        return Ok(());
    }

    // JS path: add to package.json and run install
    let pkg_json_path = project_dir.join("package.json");
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(
            "no package.json found in current directory".to_string(),
        ));
    }

    // Read current package.json as raw JSON to preserve formatting
    let content = std::fs::read_to_string(&pkg_json_path)?;
    let mut doc: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let dep_key = if save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };

    // Ensure the deps object exists
    if doc.get(dep_key).is_none() {
        doc[dep_key] = serde_json::json!({});
    }

    // Parse and add each package spec
    for spec in &js_packages {
        let (name, range) = parse_package_spec(spec);
        if !json_output {
            output::info(&format!("Adding {}@{} to {}", name.bold(), range, dep_key));
        }
        doc[dep_key][&name] = serde_json::Value::String(range);
    }

    // Write updated package.json
    let updated =
        serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
    std::fs::write(&pkg_json_path, format!("{updated}\n"))?;

    // Remove lockfile to force re-resolution with new deps
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    if lockfile_path.exists() {
        std::fs::remove_file(&lockfile_path)?;
    }

    // Run full install (pass allow_new and force through)
    run_with_options(
        client,
        project_dir,
        json_output,
        false, // offline
        force,
        allow_new,
        None,  // linker_override
        false, // no_skills
        false, // no_editor_setup
        false, // no_security_summary
        false, // auto_build
    )
    .await
}

/// Install a Swift package via SE-0292 registry: edit Package.swift + resolve.
async fn run_swift_install(
    project_dir: &Path,
    name: &lpm_common::PackageName,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
    json_output: bool,
    registry_url: &str,
) -> Result<(), LpmError> {
    use crate::swift_manifest;
    use crate::xcode_project;

    let se0292_id = swift_manifest::lpm_to_se0292_id(name);
    let product_name = ver_meta.swift_product_name().unwrap_or_else(|| &name.name);

    // Detect project type: SPM (Package.swift) vs Xcode (.xcodeproj)
    let manifest_path = swift_manifest::find_package_swift(project_dir);
    let xcodeproj_path = xcode_project::find_xcodeproj(project_dir);

    match (manifest_path, xcodeproj_path) {
        // Both exist or only SPM → use existing SPM flow
        (Some(manifest), _) => {
            run_swift_install_spm(
                project_dir,
                &manifest,
                name,
                version,
                ver_meta,
                &se0292_id,
                product_name,
                json_output,
                registry_url,
            )
            .await
        }
        // Only Xcode project → new Xcode wrapper flow
        (None, Some(xcodeproj)) => {
            run_swift_install_xcode(
                project_dir,
                &xcodeproj,
                name,
                version,
                ver_meta,
                &se0292_id,
                product_name,
                json_output,
                registry_url,
            )
            .await
        }
        // Neither
        (None, None) => Err(LpmError::Registry(
            "No Package.swift or .xcodeproj found. Initialize a Swift project first.".into(),
        )),
    }
}

/// Install a Swift package into an SPM project.
#[allow(clippy::too_many_arguments)]
async fn run_swift_install_spm(
    project_dir: &Path,
    manifest_path: &Path,
    name: &lpm_common::PackageName,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
    se0292_id: &str,
    product_name: &str,
    json_output: bool,
    registry_url: &str,
) -> Result<(), LpmError> {
    use crate::swift_manifest;

    let manifest_dir = manifest_path.parent().unwrap_or(project_dir);

    if !json_output {
        output::info(&format!(
            "Installing {} via SE-0292 registry → {}",
            name.scoped().bold(),
            se0292_id.dimmed(),
        ));
    }

    // Detect targets
    let targets = swift_manifest::get_spm_targets(manifest_dir).unwrap_or_default();
    let target_name = if targets.len() == 1 {
        targets[0].clone()
    } else if targets.len() > 1 {
        let mut sel = cliclack::select("Which target should use this dependency?");
        for (i, target) in targets.iter().enumerate() {
            sel = sel.item(target.clone(), target, "");
            if i == 0 {
                sel = sel.initial_value(target.clone());
            }
        }
        sel.interact()
            .map_err(|e| LpmError::Registry(format!("prompt failed: {e}")))?
    } else {
        return Err(LpmError::Registry(
            "No non-test targets found in Package.swift.".into(),
        ));
    };

    // Edit Package.swift
    let edit = swift_manifest::add_registry_dependency(
        manifest_path,
        se0292_id,
        version,
        product_name,
        &target_name,
    )?;

    if edit.already_exists {
        if !json_output {
            output::info(&format!(
                "{} is already in Package.swift",
                se0292_id.dimmed()
            ));
        }
    } else if !json_output {
        output::success(&format!(
            "Added .package(id: \"{}\", from: \"{}\")",
            se0292_id, version
        ));
        output::success(&format!(
            "Added .product(name: \"{}\") to target {}",
            product_name,
            target_name.bold()
        ));
    }

    // Resolve
    if !edit.already_exists {
        // Auto-configure registry scope if needed
        crate::commands::swift_registry::ensure_configured(registry_url, manifest_dir, json_output)
            .await?;

        if !json_output {
            output::info("Resolving Swift packages...");
        }
        swift_manifest::run_swift_resolve(manifest_dir)?;
    }

    // Output
    if json_output {
        let json = serde_json::json!({
            "package": name.scoped(),
            "version": version,
            "mode": "registry",
            "se0292_id": se0292_id,
            "product_name": product_name,
            "target": target_name,
            "already_existed": edit.already_exists,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if !edit.already_exists {
        println!();
        output::success(&format!(
            "Installed {}@{} via SE-0292 registry",
            name.scoped().bold(),
            version,
        ));
        println!("  import {} // in your Swift code", product_name.bold());
    }

    // Security check
    if ver_meta.has_security_issues() && !json_output {
        crate::commands::add::print_security_warnings(&name.scoped(), version, ver_meta);
    }

    if !json_output && !edit.already_exists {
        println!();
    }

    Ok(())
}

/// Install a Swift package into an Xcode app project via local wrapper package.
#[allow(clippy::too_many_arguments)]
async fn run_swift_install_xcode(
    project_dir: &Path,
    xcodeproj_path: &Path,
    name: &lpm_common::PackageName,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
    se0292_id: &str,
    product_name: &str,
    json_output: bool,
    registry_url: &str,
) -> Result<(), LpmError> {
    use crate::swift_manifest;
    use crate::xcode_project;

    // Resolve the project root (xcodeproj's parent)
    let project_root = xcodeproj_path.parent().unwrap_or(project_dir);

    if !json_output {
        output::info(&format!(
            "Installing {} via SE-0292 registry → {} (Xcode project)",
            name.scoped().bold(),
            se0292_id.dimmed(),
        ));
    }

    // Step 1: Ensure LPMDependencies wrapper package exists
    let wrapper = swift_manifest::ensure_wrapper_package(project_root)?;
    if wrapper.created && !json_output {
        output::success("Created Packages/LPMDependencies/ wrapper package");
    }

    // Step 2: Add the registry dependency to the wrapper Package.swift
    let edit = swift_manifest::add_wrapper_dependency(
        &wrapper.manifest_path,
        se0292_id,
        version,
        product_name,
    )?;

    if edit.already_exists {
        if !json_output {
            output::info(&format!("{} is already installed", se0292_id.dimmed()));
        }
    } else if !json_output {
        output::success(&format!(
            "Added .package(id: \"{}\", from: \"{}\")",
            se0292_id, version,
        ));
    }

    // Step 3: Link to Xcode project (pbxproj editing — first install only)
    let link_result = xcode_project::link_local_package(
        xcodeproj_path,
        swift_manifest::LPM_DEPS_PACKAGE_NAME,
        swift_manifest::LPM_DEPS_REL_PATH,
    )?;

    if link_result.package_ref_added && !json_output {
        output::success(&format!(
            "Linked LPMDependencies to Xcode target {}",
            link_result.target_name.bold(),
        ));
    }

    // Step 4: Resolve Swift packages
    if !edit.already_exists {
        // Auto-configure registry scope if needed
        let wrapper_dir = wrapper.manifest_path.parent().unwrap_or(project_root);
        crate::commands::swift_registry::ensure_configured(registry_url, wrapper_dir, json_output)
            .await?;

        if !json_output {
            output::info("Resolving Swift packages...");
        }
        swift_manifest::run_swift_resolve(wrapper_dir)?;
    }

    // Step 5: Output
    if json_output {
        let json = serde_json::json!({
            "package": name.scoped(),
            "version": version,
            "mode": "registry",
            "project_type": "xcode",
            "se0292_id": se0292_id,
            "product_name": product_name,
            "wrapper_package": "Packages/LPMDependencies",
            "xcode_target": link_result.target_name,
            "already_existed": edit.already_exists,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if !edit.already_exists {
        println!();
        output::success(&format!(
            "Installed {}@{} via SE-0292 registry",
            name.scoped().bold(),
            version,
        ));
        println!("  import {} // in your Swift code", product_name.bold());
    }

    // Security check
    if ver_meta.has_security_issues() && !json_output {
        crate::commands::add::print_security_warnings(&name.scoped(), version, ver_meta);
    }

    // Xcode warning (first link only)
    if link_result.package_ref_added && !json_output {
        println!();
        output::warn("If Xcode is open, close and reopen the project to pick up changes.");
    }

    if !json_output && !edit.already_exists {
        println!();
    }

    Ok(())
}

/// Parse a package spec like `express@^4.0.0` into (name, range).
/// If no range is specified, defaults to `*` (latest).
fn parse_package_spec(spec: &str) -> (String, String) {
    // Handle scoped packages: @scope/name@version
    if let Some(stripped) = spec.strip_prefix('@') {
        // Find the second @ (version separator)
        if let Some(at_pos) = stripped.find('@') {
            let at_pos = at_pos + 1; // adjust for the stripped '@'
            return (spec[..at_pos].to_string(), spec[at_pos + 1..].to_string());
        }
        // No version specified for scoped package
        return (spec.to_string(), "*".to_string());
    }

    // Unscoped: name@version
    if let Some(at_pos) = spec.find('@') {
        (spec[..at_pos].to_string(), spec[at_pos + 1..].to_string())
    } else {
        (spec.to_string(), "*".to_string())
    }
}

/// Resolve the user-specified version range against a package's available versions.
///
/// When the user specifies a version (e.g., `@1.0.0` or `@^2.0.0`), find the best
/// matching version from metadata. When no version is specified (`*`), fall back to
/// `latest_ver`.
///
/// Returns the resolved version string.
fn resolve_version_from_spec<'a>(
    range_spec: &str,
    metadata: &'a lpm_registry::PackageMetadata,
    latest_ver: &'a str,
) -> Result<&'a str, LpmError> {
    // If no version specified (wildcard), use latest
    if range_spec == "*" {
        return Ok(latest_ver);
    }

    let range = lpm_semver::VersionReq::parse(range_spec).map_err(|_| {
        LpmError::InvalidVersionRange(format!("invalid version range: {range_spec}"))
    })?;

    // Parse all available versions and find the best match
    let mut parsed_versions: Vec<(lpm_semver::Version, &str)> = metadata
        .versions
        .keys()
        .filter_map(|v_str| {
            lpm_semver::Version::parse(v_str)
                .ok()
                .map(|v| (v, v_str.as_str()))
        })
        .collect();

    // Sort so max_satisfying-style logic works
    parsed_versions.sort_by(|a, b| a.0.cmp(&b.0));

    // Find the highest version satisfying the range
    let best = parsed_versions.iter().rev().find(|(v, _)| range.matches(v));

    match best {
        Some((_, ver_str)) => Ok(ver_str),
        None => Err(LpmError::NotFound(format!(
            "no version matching {range_spec} found (available: {})",
            metadata
                .versions
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

fn make_spinner(msg: &str) -> cliclack::ProgressBar {
    let spinner = cliclack::spinner();
    spinner.start(msg);
    spinner
}

/// Auto-install agent skills for direct LPM packages.
///
/// For each direct LPM dependency, fetches its skills from the registry and
/// writes them to `.lpm/skills/{owner.package}/`. Also ensures `.gitignore`
/// includes the skills directory and triggers editor auto-integration.
async fn install_skills_for_packages(
    client: &Arc<RegistryClient>,
    packages: &[String],
    project_dir: &Path,
    no_editor_setup: bool,
) {
    // Fetch all package skills in parallel
    let futures: Vec<_> = packages
        .iter()
        .map(|pkg_name| {
            let client = client.clone();
            let pkg = pkg_name.clone();
            async move {
                let short_name = pkg.strip_prefix("@lpm.dev/").unwrap_or(&pkg).to_string();
                let result = client.get_skills(&short_name, None).await;
                (short_name, result)
            }
        })
        .collect();

    let results = futures::future::join_all(futures).await;

    let mut total_installed = 0;

    for (short_name, result) in results {
        match result {
            Ok(response) if !response.skills.is_empty() => {
                let skills_dir = project_dir.join(".lpm").join("skills").join(&short_name);
                let _ = std::fs::create_dir_all(&skills_dir);

                for skill in &response.skills {
                    if !lpm_common::is_safe_skill_name(&skill.name) {
                        tracing::warn!("skipping skill with unsafe name: {}", skill.name);
                        continue;
                    }

                    let content = skill
                        .raw_content
                        .as_deref()
                        .or(skill.content.as_deref())
                        .unwrap_or("");
                    if !content.is_empty() {
                        let path = skills_dir.join(format!("{}.md", skill.name));
                        let _ = std::fs::write(&path, content);
                        total_installed += 1;
                    }
                }
            }
            _ => {} // No skills or API error — skip silently
        }
    }

    if total_installed > 0 {
        output::info(&format!("Installed {total_installed} agent skill(s)"));

        // Ensure .gitignore includes .lpm/skills/
        ensure_skills_gitignore(project_dir);

        // Auto-integrate with editors (respects --no-editor-setup)
        if !no_editor_setup {
            let integrations = crate::editor_skills::auto_integrate_skills(project_dir);
            for msg in &integrations {
                output::info(msg);
            }
        }
    }
}

/// Ensure `.gitignore` contains an entry for `.lpm/skills/`.
pub fn ensure_skills_gitignore(project_dir: &Path) {
    let gitignore_path = project_dir.join(".gitignore");
    let marker = ".lpm/skills/";

    if gitignore_path.exists() {
        let content = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        if content.lines().any(|l| l.trim() == marker) {
            return; // Already present
        }
        // Append using OpenOptions to reduce TOCTOU window vs read-then-write
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .open(&gitignore_path)
        {
            if !content.ends_with('\n') {
                let _ = writeln!(file);
            }
            let _ = writeln!(file);
            let _ = writeln!(file, "# LPM Agent Skills (auto-generated)");
            let _ = writeln!(file, "{marker}");
        }
    } else {
        let _ = std::fs::write(&gitignore_path, format!("# LPM Agent Skills\n{marker}\n"));
    }
}

/// Read `lpm.scripts.autoBuild` from package.json.
fn read_auto_build_config(project_dir: &Path) -> bool {
    let pkg_json_path = project_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_json_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };

    parsed
        .get("lpm")
        .and_then(|l| l.get("scripts"))
        .and_then(|s| s.get("autoBuild"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PackageMetadata with the given version strings and latest tag.
    fn make_metadata(versions: &[&str], latest: &str) -> lpm_registry::PackageMetadata {
        let mut version_map = std::collections::HashMap::new();
        for &v in versions {
            version_map.insert(
                v.to_string(),
                lpm_registry::VersionMetadata {
                    name: "@lpm.dev/acme.swift-logger".to_string(),
                    version: v.to_string(),
                    description: None,
                    dependencies: Default::default(),
                    dev_dependencies: Default::default(),
                    peer_dependencies: Default::default(),
                    optional_dependencies: Default::default(),
                    os: vec![],
                    cpu: vec![],
                    dist: None,
                    readme: None,
                    lpm_config: None,
                    ecosystem: Some("swift".to_string()),
                    swift_meta: None,
                    behavioral_tags: None,
                    lifecycle_scripts: None,
                    security_findings: None,
                    quality_score: None,
                    vulnerabilities: None,
                },
            );
        }

        let mut dist_tags = std::collections::HashMap::new();
        dist_tags.insert("latest".to_string(), latest.to_string());

        lpm_registry::PackageMetadata {
            name: "@lpm.dev/acme.swift-logger".to_string(),
            description: None,
            dist_tags,
            versions: version_map,
            time: Default::default(),
            downloads: None,
            distribution_mode: None,
            package_type: None,
            latest_version: Some(latest.to_string()),
            ecosystem: Some("swift".to_string()),
        }
    }

    // ── parse_package_spec ──────────────────────────────────────────

    #[test]
    fn parse_spec_scoped_with_exact_version() {
        let (name, range) = parse_package_spec("@lpm.dev/acme.swift-logger@1.0.0");
        assert_eq!(name, "@lpm.dev/acme.swift-logger");
        assert_eq!(range, "1.0.0");
    }

    #[test]
    fn parse_spec_scoped_with_caret_version() {
        let (name, range) = parse_package_spec("@lpm.dev/acme.swift-logger@^2.0.0");
        assert_eq!(name, "@lpm.dev/acme.swift-logger");
        assert_eq!(range, "^2.0.0");
    }

    #[test]
    fn parse_spec_scoped_no_version() {
        let (name, range) = parse_package_spec("@lpm.dev/acme.swift-logger");
        assert_eq!(name, "@lpm.dev/acme.swift-logger");
        assert_eq!(range, "*");
    }

    // ── resolve_version_from_spec ───────────────────────────────────

    #[test]
    fn resolve_wildcard_returns_latest() {
        let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");
        let result = resolve_version_from_spec("*", &meta, "3.0.0").unwrap();
        assert_eq!(result, "3.0.0");
    }

    #[test]
    fn resolve_exact_version_returns_that_version() {
        let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");
        let result = resolve_version_from_spec("1.0.0", &meta, "3.0.0").unwrap();
        assert_eq!(result, "1.0.0");
    }

    #[test]
    fn resolve_caret_range_returns_best_match() {
        let meta = make_metadata(&["1.0.0", "1.5.0", "2.0.0", "2.1.0"], "2.1.0");
        let result = resolve_version_from_spec("^1.0.0", &meta, "2.1.0").unwrap();
        assert_eq!(result, "1.5.0");
    }

    #[test]
    fn resolve_tilde_range_returns_best_match() {
        let meta = make_metadata(&["1.0.0", "1.0.5", "1.1.0", "2.0.0"], "2.0.0");
        let result = resolve_version_from_spec("~1.0.0", &meta, "2.0.0").unwrap();
        assert_eq!(result, "1.0.5");
    }

    #[test]
    fn resolve_no_match_returns_error() {
        let meta = make_metadata(&["1.0.0", "1.5.0"], "1.5.0");
        let result = resolve_version_from_spec("^3.0.0", &meta, "1.5.0");
        assert!(result.is_err());
    }

    /// This is the exact bug scenario: user specifies `@1.0.0` but the code
    /// previously ignored it and used `latest_ver` (3.0.0) instead.
    #[test]
    fn bug_version_spec_not_ignored_for_swift_packages() {
        let meta = make_metadata(&["1.0.0", "2.0.0", "3.0.0"], "3.0.0");

        // User asked for @1.0.0 — must get 1.0.0, NOT 3.0.0
        let result = resolve_version_from_spec("1.0.0", &meta, "3.0.0").unwrap();
        assert_eq!(
            result, "1.0.0",
            "user-specified version @1.0.0 should be respected, not silently replaced with latest"
        );

        // User asked for @^2.0.0 — must get 2.0.0, NOT 3.0.0
        let result = resolve_version_from_spec("^2.0.0", &meta, "3.0.0").unwrap();
        assert_eq!(
            result, "2.0.0",
            "user-specified range @^2.0.0 should resolve to 2.0.0, not latest"
        );
    }

    #[test]
    fn ensure_skills_gitignore_appends_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

        ensure_skills_gitignore(dir.path());

        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(content.contains(".lpm/skills/"), "entry should be added");
        assert!(
            content.contains("node_modules/"),
            "existing content preserved"
        );
    }

    #[test]
    fn ensure_skills_gitignore_no_duplicate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();

        ensure_skills_gitignore(dir.path());
        ensure_skills_gitignore(dir.path());

        let content = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        let count = content.matches(".lpm/skills/").count();
        assert_eq!(count, 1, "should not duplicate entry");
    }

    // ── is_install_up_to_date ──────────────────────────────────────

    /// Set up a tempdir that looks like a post-install project:
    /// package.json, lpm.lock, node_modules/, .lpm/install-hash.
    fn setup_installed_project(dir: &std::path::Path) {
        let pkg = r#"{"name":"test","dependencies":{"lodash":"^4.0.0"}}"#;
        let lock = "[packages]\nname = \"lodash\"\nversion = \"4.17.21\"\n";

        std::fs::write(dir.join("package.json"), pkg).unwrap();
        std::fs::write(dir.join("lpm.lock"), lock).unwrap();
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();

        let hash = super::super::dev::compute_install_hash(pkg, lock);
        std::fs::create_dir_all(dir.join(".lpm")).unwrap();
        std::fs::write(dir.join(".lpm").join("install-hash"), &hash).unwrap();
    }

    #[test]
    fn fast_exit_when_everything_matches() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        assert!(
            is_install_up_to_date(dir.path()),
            "should be up to date when hash matches and node_modules is clean"
        );
    }

    #[test]
    fn fast_exit_fails_when_package_json_changed() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        // Simulate adding a new dependency
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"test","dependencies":{"lodash":"^4.0.0","express":"^4.0.0"}}"#,
        )
        .unwrap();

        assert!(
            !is_install_up_to_date(dir.path()),
            "should NOT be up to date when package.json changed"
        );
    }

    #[test]
    fn fast_exit_fails_when_lockfile_changed() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        // Simulate lockfile update
        std::fs::write(
            dir.path().join("lpm.lock"),
            "[packages]\nname = \"lodash\"\nversion = \"4.17.22\"\n",
        )
        .unwrap();

        assert!(
            !is_install_up_to_date(dir.path()),
            "should NOT be up to date when lockfile changed"
        );
    }

    #[test]
    fn fast_exit_fails_when_no_lockfile() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());
        std::fs::remove_file(dir.path().join("lpm.lock")).unwrap();

        assert!(
            !is_install_up_to_date(dir.path()),
            "should NOT be up to date when lockfile is missing"
        );
    }

    #[test]
    fn fast_exit_fails_when_no_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());
        std::fs::remove_dir_all(dir.path().join("node_modules")).unwrap();

        assert!(
            !is_install_up_to_date(dir.path()),
            "should NOT be up to date when node_modules is missing"
        );
    }

    #[test]
    fn fast_exit_fails_when_no_hash_file() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());
        std::fs::remove_file(dir.path().join(".lpm").join("install-hash")).unwrap();

        assert!(
            !is_install_up_to_date(dir.path()),
            "should NOT be up to date when install-hash is missing"
        );
    }

    #[test]
    fn fast_exit_fails_when_node_modules_modified() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        // Touch node_modules AFTER the hash was written — simulates
        // external modification (user deleted a package folder, etc.)
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::create_dir_all(dir.path().join("node_modules").join("new-pkg")).unwrap();

        assert!(
            !is_install_up_to_date(dir.path()),
            "should NOT be up to date when node_modules was modified after hash"
        );
    }

    #[test]
    fn fast_exit_on_empty_project() {
        let dir = tempfile::tempdir().unwrap();
        // Completely empty directory — no package.json at all
        assert!(
            !is_install_up_to_date(dir.path()),
            "should NOT be up to date on empty directory"
        );
    }

    /// Verify that --force is defined as a CLI flag on the Install command.
    /// This is a structural test — ensures the flag doesn't get accidentally removed.
    #[test]
    fn force_flag_defined_in_cli() {
        use clap::Parser;

        // Parse with --force — should succeed
        let result = crate::Cli::try_parse_from(["lpm", "install", "--force"]);
        assert!(
            result.is_ok(),
            "lpm install --force should be a valid command: {:?}",
            result.err()
        );
    }

    /// Verify that --force can be combined with other install flags.
    #[test]
    fn force_flag_combines_with_other_flags() {
        use clap::Parser;

        let result =
            crate::Cli::try_parse_from(["lpm", "install", "--force", "--offline", "--allow-new"]);
        assert!(
            result.is_ok(),
            "lpm install --force --offline --allow-new should parse: {:?}",
            result.err()
        );
    }

    /// Verify is_install_up_to_date returns true for a properly set up project,
    /// confirming that --force's bypass of this check is meaningful.
    #[test]
    fn force_bypass_is_meaningful() {
        let dir = tempfile::tempdir().unwrap();
        setup_installed_project(dir.path());

        // Without --force, this returns true (fast exit)
        assert!(
            is_install_up_to_date(dir.path()),
            "project should be up-to-date — --force bypasses this"
        );

        // With --force, the guard `!force && ... && is_install_up_to_date()`
        // short-circuits, so is_install_up_to_date is never called.
        // We can't test the full pipeline here (needs registry), but we
        // verify that the bypass target exists and returns true.
    }
}
