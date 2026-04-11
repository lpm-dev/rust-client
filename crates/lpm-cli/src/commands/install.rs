use crate::output;
use indicatif::{ProgressBar, ProgressStyle}; // kept for concurrent download progress bar
use lpm_common::LpmError;
use lpm_linker::LinkTarget;
use lpm_registry::RegistryClient;
use lpm_resolver::{ResolvedPackage, check_unmet_peers, resolve_dependencies_with_overrides};
use lpm_store::PackageStore;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Maximum number of concurrent tarball downloads.
const MAX_CONCURRENT_DOWNLOADS: usize = 16;

/// A workspace member dependency that lives at a source directory inside the
/// current workspace and must be linked locally instead of fetched from the
/// registry. Produced by [`extract_workspace_protocol_deps`] and consumed by
/// [`link_workspace_members`].
///
/// **Phase 32 Phase 2 audit fix #3** (workspace:^ resolver bug):
/// Pre-fix, [`lpm_workspace::resolve_workspace_protocol`] rewrote
/// `"@scope/member": "workspace:^"` into `"@scope/member": "^1.5.0"` and left
/// the entry in `deps`, which then went to the registry resolver and 404'd
/// against npm/upstream because unpublished workspace members can't be fetched
/// remotely. Post-fix, [`extract_workspace_protocol_deps`] strips these
/// entries from `deps` BEFORE the resolver runs and returns them as
/// `WorkspaceMemberLink`s; [`link_workspace_members`] then symlinks them into
/// `node_modules/<name>` directly from the member's source directory after
/// the install pipeline finishes.
#[derive(Debug, Clone)]
struct WorkspaceMemberLink {
    /// Package name as declared in the member's package.json (e.g., `@test/core`).
    name: String,
    /// Concrete version from the member's own package.json `version` field.
    /// Used only for diagnostics — there is no resolver constraint to satisfy.
    version: String,
    /// Absolute path to the member's source directory (the parent of its
    /// `package.json`). The post-link symlink target.
    source_dir: PathBuf,
}

/// Strip `workspace:*` / `workspace:^` / `workspace:~` / `workspace:<exact>`
/// dependencies from `deps` and return them as a list of locally-resolvable
/// links. The resolver never sees these entries — they bypass the registry
/// entirely and are linked from disk by [`link_workspace_members`].
///
/// **Phase 32 Phase 2 audit fix #3:** this replaces the previous
/// "[`lpm_workspace::resolve_workspace_protocol`] rewrites in place, then the
/// resolver fetches from the registry" pattern, which 404'd whenever a
/// workspace member was unpublished (the common case in monorepos that
/// internally develop libraries before any release).
///
/// Returns `Err(LpmError::Workspace)` if a `workspace:` reference points at a
/// package name that is not in the workspace's discovered member list. This
/// preserves the validation behavior of `resolve_workspace_protocol` so that
/// typos in cross-member deps still hard-error instead of silently shipping
/// no dependency.
///
/// Members are matched by their declared `package.json` `name` field, not by
/// directory name. The version field is read from the member's own
/// `package.json` (defaulting to `0.0.0` if absent, mirroring how
/// `resolve_workspace_protocol` handled the same case).
fn extract_workspace_protocol_deps(
    deps: &mut HashMap<String, String>,
    workspace: &lpm_workspace::Workspace,
) -> Result<Vec<WorkspaceMemberLink>, LpmError> {
    // First pass: identify the names of workspace: entries. We can't mutate
    // `deps` while iterating it, so we collect the names + their original
    // protocol strings, then validate + remove in a second pass.
    let mut workspace_names: Vec<(String, String)> = deps
        .iter()
        .filter(|(_, range)| range.starts_with("workspace:"))
        .map(|(name, range)| (name.clone(), range.clone()))
        .collect();

    // Deterministic order so the returned list (and any error message) is
    // stable for tests + JSON output. HashMap iteration order is randomized.
    workspace_names.sort_by(|a, b| a.0.cmp(&b.0));

    if workspace_names.is_empty() {
        return Ok(Vec::new());
    }

    let mut extracted = Vec::with_capacity(workspace_names.len());
    for (name, range) in &workspace_names {
        let member = workspace
            .members
            .iter()
            .find(|m| m.package.name.as_deref() == Some(name.as_str()))
            .ok_or_else(|| {
                let mut available: Vec<&str> = workspace
                    .members
                    .iter()
                    .filter_map(|m| m.package.name.as_deref())
                    .collect();
                available.sort();
                let available_str = if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                };
                LpmError::Workspace(format!(
                    "{range} references package '{name}' which is not a workspace member. \
                     Available members: {available_str}"
                ))
            })?;

        let version = member
            .package
            .version
            .as_deref()
            .unwrap_or("0.0.0")
            .to_string();

        extracted.push(WorkspaceMemberLink {
            name: name.clone(),
            version,
            source_dir: member.path.clone(),
        });
    }

    // Validation passed for every entry — now remove them from `deps`.
    for (name, _) in &workspace_names {
        deps.remove(name);
    }

    Ok(extracted)
}

/// Symlink workspace member dependencies into `<project_dir>/node_modules/<name>`.
///
/// Called AFTER `link_packages` (or `link_packages_hoisted`) so that the
/// linker's stale-symlink cleanup pass — which removes any
/// `node_modules/<name>` entry not in `direct_names` — has already run. Our
/// workspace symlinks are not in `direct_names` because workspace members are
/// stripped from `deps` before resolution by [`extract_workspace_protocol_deps`],
/// so they would be wiped on every install if we created them BEFORE the
/// linker. The post-link order also means the helper has to be idempotent
/// across re-runs (it cleans any pre-existing entry at the link path).
///
/// Returns the number of symlinks created.
fn link_workspace_members(
    project_dir: &Path,
    members: &[WorkspaceMemberLink],
) -> Result<usize, LpmError> {
    if members.is_empty() {
        return Ok(0);
    }

    let node_modules = project_dir.join("node_modules");
    std::fs::create_dir_all(&node_modules).map_err(LpmError::Io)?;

    let mut linked = 0usize;
    for member in members {
        lpm_linker::link_workspace_member(&node_modules, &member.name, &member.source_dir)
            .map_err(|e| {
                LpmError::Workspace(format!(
                    "failed to link workspace member {}: {e}",
                    member.name
                ))
            })?;
        linked += 1;
    }
    Ok(linked)
}

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
    // Phase 32 Phase 2: when invoked from the workspace-aware install path,
    // the list of `package.json` files that were modified before this call.
    // Surfaced in the JSON output as `target_set` so agents can see which
    // workspace members were touched. `None` for legacy/standalone callers.
    target_set: Option<&[String]>,
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
        let total_ms = elapsed.as_millis();
        if json_output {
            // Emit the same `timing` object shape as the main and offline paths
            // so benchmark scripts can parse install output uniformly regardless
            // of which fast-path was taken. Stages are zero because no real work
            // ran — the entire pipeline was skipped.
            let mut json = serde_json::json!({
                "success": true,
                "up_to_date": true,
                "duration_ms": total_ms as u64,
                "timing": {
                    "resolve_ms": 0u128,
                    "fetch_ms": 0u128,
                    "link_ms": 0u128,
                    "total_ms": total_ms,
                },
            });
            // Phase 2: surface workspace target set for agents.
            if let Some(targets) = target_set {
                json["target_set"] =
                    serde_json::Value::Array(targets.iter().map(|s| serde_json::json!(s)).collect());
            }
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            // Header already printed at function entry.
            output::success(&format!("up to date ({total_ms}ms)"));
        }
        return Ok(());
    }

    let pkg_name = pkg.name.as_deref().unwrap_or("(unnamed)");
    if !json_output {
        output::info(&format!("Installing dependencies for {}", pkg_name.bold()));
    }

    let mut deps = pkg.dependencies.clone();

    // Resolve `catalog:` protocols and EXTRACT `workspace:*` member references
    // before anything else (lockfile fast path, resolver). This ensures the
    // `deps` HashMap contains only real registry ranges by the time the
    // resolver sees it.
    //
    // **Phase 32 Phase 2 audit fix #3 (workspace:^ resolver bug):** previously
    // we called `lpm_workspace::resolve_workspace_protocol` which rewrote
    // `"@scope/member": "workspace:^"` to `"@scope/member": "^1.5.0"` and
    // LEFT IT in `deps`. The resolver then tried to fetch
    // `@scope/member@^1.5.0` from npm/lpm.dev and 404'd against the upstream
    // proxy, because unpublished workspace members can't be looked up
    // remotely. Post-fix, we strip workspace member references from `deps`
    // entirely; they are linked from disk after the install pipeline
    // finishes via [`link_workspace_members`].
    //
    // Catalog resolution must use the workspace ROOT catalogs when inside a
    // workspace, because workspace members define `"catalog:"` references
    // that point to centralized version definitions in the root package.json.
    let workspace = lpm_workspace::discover_workspace(project_dir)
        .ok()
        .flatten();

    let workspace_member_deps: Vec<WorkspaceMemberLink> = if let Some(ref ws) = workspace {
        // workspace:* extraction (NEW: replaces resolve_workspace_protocol)
        let extracted = extract_workspace_protocol_deps(&mut deps, ws)?;
        if !extracted.is_empty() && !json_output {
            for member in &extracted {
                tracing::debug!(
                    "workspace member (local): {} @ {} from {}",
                    member.name,
                    member.version,
                    member.source_dir.display()
                );
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
        extracted
    } else {
        // Standalone project (no workspace): no workspace member deps possible.
        // Local catalogs are still resolved if present.
        if !pkg.catalogs.is_empty() {
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
        Vec::new()
    };

    if deps.is_empty() && workspace_member_deps.is_empty() {
        // Phase 32 Phase 2 audit fix: emit a proper JSON object even on the
        // empty-deps short-circuit so agents driving install always get a
        // parseable result. Pre-fix this branch returned silently in JSON
        // mode, which combined with the workspace-aware filtered install
        // path produced a complete output silence on fresh workspaces.
        let elapsed = start.elapsed();
        let total_ms = elapsed.as_millis();
        if json_output {
            let mut json = serde_json::json!({
                "success": true,
                "no_dependencies": true,
                "duration_ms": total_ms as u64,
                "timing": {
                    "resolve_ms": 0u128,
                    "fetch_ms": 0u128,
                    "link_ms": 0u128,
                    "total_ms": total_ms,
                },
            });
            if let Some(targets) = target_set {
                json["target_set"] = serde_json::Value::Array(
                    targets.iter().map(|s| serde_json::json!(s)).collect(),
                );
            }
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
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
                "--offline requires a lockfile. Run `lpm install` online first.".into(),
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
            &workspace_member_deps,
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

    // Phase 32 Phase 2 audit fix #3: link workspace member dependencies AFTER
    // the regular linker run. The linker's stale-symlink cleanup pass at the
    // top of `link_packages` would otherwise wipe these symlinks on every
    // install (they're not in `direct_names` because workspace members were
    // stripped from `deps` before resolution by `extract_workspace_protocol_deps`).
    // Re-creating them here every time keeps the layout consistent.
    let workspace_links_created =
        link_workspace_members(project_dir, &workspace_member_deps)?;
    if workspace_links_created > 0 && !json_output {
        output::info(&format!(
            "Linked {} workspace member(s)",
            workspace_links_created.to_string().bold()
        ));
    }

    // Step 6: Lifecycle script security audit + trusted script execution
    let policy = lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));

    // **Phase 32 Phase 4 M3:** capture the install-time blocked set into
    // `<project_dir>/.lpm/build-state.json` so that:
    //   1. `lpm approve-builds` doesn't have to re-walk the store on startup
    //   2. The post-install warning is suppressed when the blocked set is
    //      unchanged from the previous install (the spam-prevention rule)
    //   3. Agents driving install via JSON output get a structured
    //      `blocked_count` / `blocked_set_changed` summary
    let installed_with_integrity: Vec<(String, String, Option<String>)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
        .collect();
    let blocked_capture = crate::build_state::capture_blocked_set_after_install(
        project_dir,
        &store,
        &installed_with_integrity,
        &policy,
    )?;

    // Show build hint for packages with lifecycle scripts (Phase 25: two-phase model).
    // Scripts are NEVER executed during install — use `lpm build` instead.
    // **Phase 32 Phase 4 M3:** the hint is now gated on the blocked-set
    // fingerprint changing — repeated installs of the same blocked set are silent.
    if !json_output && blocked_capture.should_emit_warning {
        if blocked_capture.all_clear_banner {
            output::success(
                "All previously-blocked packages have been approved. Run `lpm build` to execute their scripts.",
            );
        } else {
            let all_pkgs: Vec<(String, String)> = packages
                .iter()
                .map(|p| (p.name.clone(), p.version.clone()))
                .collect();
            crate::commands::build::show_install_build_hint(&store, &all_pkgs, &policy, project_dir);
            output::info(
                "Run `lpm approve-builds` to review and approve their lifecycle scripts.",
            );
        }
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
                    format!("lpm install {}", phantom.package_name).dimmed()
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

    if should_auto_build(auto_build, config_auto_build, all_trusted)
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

        let mut json = serde_json::json!({
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
        // Phase 32 Phase 2: surface workspace target set for agents.
        // None for legacy/standalone callers; Some(...) for the filtered path.
        if let Some(targets) = target_set {
            json["target_set"] =
                serde_json::Value::Array(targets.iter().map(|s| serde_json::json!(s)).collect());
        }
        // Phase 32 Phase 2 audit fix #3: surface workspace member deps that
        // were linked locally instead of going through the registry.
        if !workspace_member_deps.is_empty() {
            json["workspace_members"] = serde_json::Value::Array(
                workspace_member_deps
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "name": m.name,
                            "version": m.version,
                            "source_dir": m.source_dir.display().to_string(),
                        })
                    })
                    .collect(),
            );
        }
        // **Phase 32 Phase 4 M3:** surface the install-time blocked set so
        // agents and CI can drive `lpm approve-builds` without re-scanning.
        json["blocked_count"] = serde_json::json!(blocked_capture.state.blocked_packages.len());
        json["blocked_set_changed"] = serde_json::json!(blocked_capture.should_emit_warning);
        json["blocked_set_fingerprint"] =
            serde_json::json!(blocked_capture.state.blocked_set_fingerprint);
        json["blocked_packages"] = serde_json::Value::Array(
            blocked_capture
                .state
                .blocked_packages
                .iter()
                .map(|bp| {
                    serde_json::json!({
                        "name": bp.name,
                        "version": bp.version,
                        "integrity": bp.integrity,
                        "script_hash": bp.script_hash,
                        "phases_present": bp.phases_present,
                        "binding_drift": bp.binding_drift,
                    })
                })
                .collect(),
        );
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

fn should_auto_build(auto_build_flag: bool, config_auto_build: bool, all_trusted: bool) -> bool {
    auto_build_flag || config_auto_build || all_trusted
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
    workspace_member_deps: &[WorkspaceMemberLink],
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

    // Phase 32 Phase 2 audit fix #3: link workspace member dependencies AFTER
    // the regular linker run. Same rationale as the online path — see
    // `run_with_options`. Offline mode does not write a lockfile entry for
    // workspace members because they're never resolved through the registry.
    let workspace_links_created = link_workspace_members(project_dir, workspace_member_deps)?;
    if workspace_links_created > 0 && !json_output {
        output::info(&format!(
            "Linked {} workspace member(s)",
            workspace_links_created.to_string().bold()
        ));
    }

    // Lifecycle script security audit (two-phase model: install never runs scripts).
    // Scripts are NEVER executed during install — use `lpm build` instead.
    // This matches the online install path exactly.
    let policy = lpm_security::SecurityPolicy::from_package_json(&project_dir.join("package.json"));

    // **Phase 32 Phase 4 M3:** capture the install-time blocked set into
    // build-state.json. Same wiring as the online path — see comment there.
    let installed_with_integrity: Vec<(String, String, Option<String>)> = packages
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.integrity.clone()))
        .collect();
    let blocked_capture = crate::build_state::capture_blocked_set_after_install(
        project_dir,
        &store,
        &installed_with_integrity,
        &policy,
    )?;

    if !json_output && blocked_capture.should_emit_warning {
        if blocked_capture.all_clear_banner {
            output::success(
                "All previously-blocked packages have been approved. Run `lpm build` to execute their scripts.",
            );
        } else {
            let all_pkgs: Vec<(String, String)> = packages
                .iter()
                .map(|p| (p.name.clone(), p.version.clone()))
                .collect();
            crate::commands::build::show_install_build_hint(&store, &all_pkgs, &policy, project_dir);
            output::info(
                "Run `lpm approve-builds` to review and approve their lifecycle scripts.",
            );
        }
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

        let mut json = serde_json::json!({
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
        // Phase 32 Phase 2 audit fix #3: surface workspace member deps that
        // were linked locally instead of going through the registry.
        if !workspace_member_deps.is_empty() {
            json["workspace_members"] = serde_json::Value::Array(
                workspace_member_deps
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "name": m.name,
                            "version": m.version,
                            "source_dir": m.source_dir.display().to_string(),
                        })
                    })
                    .collect(),
            );
        }
        // **Phase 32 Phase 4 M3:** surface the install-time blocked set so
        // agents and CI can drive `lpm approve-builds` without re-scanning.
        // Mirrors the online path.
        json["blocked_count"] = serde_json::json!(blocked_capture.state.blocked_packages.len());
        json["blocked_set_changed"] = serde_json::json!(blocked_capture.should_emit_warning);
        json["blocked_set_fingerprint"] =
            serde_json::json!(blocked_capture.state.blocked_set_fingerprint);
        json["blocked_packages"] = serde_json::Value::Array(
            blocked_capture
                .state
                .blocked_packages
                .iter()
                .map(|bp| {
                    serde_json::json!({
                        "name": bp.name,
                        "version": bp.version,
                        "integrity": bp.integrity,
                        "script_hash": bp.script_hash,
                        "phases_present": bp.phases_present,
                        "binding_drift": bp.binding_drift,
                    })
                })
                .collect(),
        );
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

/// Add JS package specs to a single `package.json` file in place.
///
/// Phase 32 Phase 2 M2: extracted from `run_add_packages` so the new
/// filtered/`-w` path in `run_install_filtered_add` can mutate multiple
/// member manifests without duplicating the JSON merge logic.
///
/// Reads → mutates → atomically rewrites the manifest. Does NOT touch the
/// lockfile or run any install pipeline — those are the caller's job (and
/// happen ONCE per command, not once per target manifest).
///
/// Returns `Err(LpmError::NotFound)` if the manifest is missing,
/// `Err(LpmError::Registry)` for parse/serialize failures.
pub fn add_packages_to_manifest(
    pkg_json_path: &Path,
    package_specs: &[String],
    save_dev: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(format!(
            "no package.json at {}",
            pkg_json_path.display()
        )));
    }

    let content = std::fs::read_to_string(pkg_json_path)?;
    let mut doc: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let dep_key = if save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };

    if doc.get(dep_key).is_none() {
        doc[dep_key] = serde_json::json!({});
    }

    let target_label = pkg_json_path
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| pkg_json_path.display().to_string());

    for spec in package_specs {
        let (name, range) = parse_package_spec(spec);
        if !json_output {
            output::info(&format!(
                "Adding {}@{} to {} ({target_label})",
                name.bold(),
                range,
                dep_key
            ));
        }
        doc[dep_key][&name] = serde_json::Value::String(range);
    }

    let updated =
        serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
    std::fs::write(pkg_json_path, format!("{updated}\n"))?;
    Ok(())
}

/// Install specific packages: add them to package.json then run full install.
/// For Swift packages (ecosystem=swift), uses SE-0292 registry mode instead.
///
/// Handles specs like: `express`, `express@^4.0.0`, `@lpm.dev/neo.highlight@1.0.0`
///
/// **Phase 32 Phase 2 M2:** this is the legacy path used when no `--filter`
/// or `-w` flag is set AND we're not inside a workspace member directory.
/// New filtered paths go through `run_install_filtered_add` instead, which
/// handles workspace-aware target resolution but rejects Swift packages
/// (SE-0292 workspace support is deferred to Phase 12+).
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
    add_packages_to_manifest(
        &project_dir.join("package.json"),
        &js_packages,
        save_dev,
        json_output,
    )?;

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
        None,  // target_set: legacy single-project path
    )
    .await
}

/// Phase 32 Phase 2 M2: workspace-aware install entry point.
///
/// Resolves CLI `--filter` / `-w` / cwd into a concrete set of
/// `package.json` files via [`crate::commands::install_targets`], mutates
/// each one with the requested package specs, then runs the install
/// pipeline ONCE at the resolved `install_root`.
///
/// **Swift packages**: this path treats every package as JS — Swift
/// `ecosystem=swift` packages added through this path will be written into
/// the target `package.json` files but the SE-0292 routing in
/// `run_swift_install` will not fire. Workspace-aware Swift install is
/// tracked under Phase 12+. For pure Swift workflows, use the legacy
/// path: `cd <project> && lpm install @scope/swift-pkg` (no `-w` / `--filter`).
#[allow(clippy::too_many_arguments)]
pub async fn run_install_filtered_add(
    client: &RegistryClient,
    cwd: &Path,
    packages: &[String],
    save_dev: bool,
    filters: &[String],
    workspace_root_flag: bool,
    fail_if_no_match: bool,
    json_output: bool,
    allow_new: bool,
    force: bool,
) -> Result<(), LpmError> {
    // 1. Resolve CLI flags into a concrete target list.
    let targets = crate::commands::install_targets::resolve_install_targets(
        cwd,
        filters,
        workspace_root_flag,
        true, // has_packages — install_filtered_add is only called with non-empty packages
    )?;

    // 2. Empty result handling (--fail-if-no-match mirrors Phase 1 D3).
    //
    // Phase 2 audit follow-through: when the filter set returns empty AND
    // any filter looks like a bare name that would have substring-matched
    // pre-Phase-32, surface the same D2 substring → glob migration hint
    // that `lpm run --filter` and `lpm filter` already emit. Otherwise
    // users coming from the legacy substring matcher get a generic "no
    // packages matched" with no recovery path.
    if targets.member_manifests.is_empty() {
        let hint = crate::commands::filter::format_no_match_hint(filters);

        if fail_if_no_match {
            let base = "no workspace packages matched the filter (--fail-if-no-match)";
            return Err(LpmError::Script(match hint {
                Some(h) => format!("{base}\n\n{h}"),
                None => base.to_string(),
            }));
        }
        if !json_output {
            output::warn("No packages matched the filter; nothing to install.");
            if let Some(h) = hint {
                eprintln!();
                for line in h.lines() {
                    eprintln!("  {}", line.dimmed());
                }
                eprintln!();
            }
        }
        return Ok(());
    }

    // 3. Multi-member preview line (informational only — Phase 2 ships
    //    without an interactive y/N prompt; the JSON output mode and the
    //    `--fail-if-no-match` flag give CI users the safety net they need).
    if targets.multi_member && !json_output {
        output::info(&format!(
            "Adding {} package(s) to {} workspace member(s):",
            packages.len(),
            targets.member_manifests.len(),
        ));
        for path in &targets.member_manifests {
            let label = path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            println!("  {}", label.dimmed());
        }
    }

    // 4. Iterate per target. For EACH targeted manifest:
    //    a. Mutate the manifest with the new package entries.
    //    b. Remove that member's lockfile to force re-resolution.
    //    c. Run the install pipeline AT THE MEMBER'S DIR (not at the
    //       workspace root). LPM uses per-directory lockfiles + node_modules,
    //       so this is the only place the new dependency will be installed
    //       and linked correctly.
    //
    // This is the Phase 2 audit correction. The original Phase 2 design ran
    // a single install pipeline at the workspace root, which silently
    // dropped member-targeted installs on workspaces with no root deps.
    //
    // For multi-target filtered installs (`--filter "ui-*"` matching N
    // members), the pipeline runs N times sequentially. JSON output mode
    // produces N JSON objects on stdout (JSON-Lines), one per member.
    let target_paths: Vec<String> = targets
        .member_manifests
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    let mut last_err: Option<LpmError> = None;
    for manifest_path in &targets.member_manifests {
        // (a) Mutate the target manifest.
        add_packages_to_manifest(manifest_path, packages, save_dev, json_output)?;

        let install_root =
            crate::commands::install_targets::install_root_for(manifest_path).to_path_buf();

        // (b) Remove this member's lockfile so the resolver re-runs.
        let lockfile_path = install_root.join(lpm_lockfile::LOCKFILE_NAME);
        if lockfile_path.exists() {
            std::fs::remove_file(&lockfile_path)?;
        }

        // (c) Run the install pipeline at THIS member's directory.
        // For each call, target_set carries the full multi-target list so
        // every per-member JSON object identifies the broader operation.
        let result = run_with_options(
            client,
            &install_root,
            json_output,
            false, // offline
            force,
            allow_new,
            None,  // linker_override
            false, // no_skills
            false, // no_editor_setup
            false, // no_security_summary
            false, // auto_build
            Some(&target_paths),
        )
        .await;

        if let Err(e) = result {
            // Surface the first failure but keep going so subsequent
            // members are still attempted? No — abort on first failure.
            // Half-installed multi-member states are confusing and the user
            // should fix the failure before retrying.
            last_err = Some(e);
            break;
        }
    }

    if let Some(e) = last_err {
        return Err(e);
    }
    Ok(())
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

    #[test]
    fn auto_build_trigger_enables_when_any_current_source_requests_it() {
        assert!(should_auto_build(true, false, false));
        assert!(should_auto_build(false, true, false));
        assert!(should_auto_build(false, false, true));
        assert!(!should_auto_build(false, false, false));
    }

    #[test]
    fn read_auto_build_config_reads_nested_lpm_flag() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"lpm":{"scripts":{"autoBuild":true}}}"#,
        )
        .unwrap();

        assert!(read_auto_build_config(dir.path()));
    }

    #[test]
    fn read_auto_build_config_defaults_false_for_missing_or_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"name":"demo"}"#).unwrap();
        assert!(!read_auto_build_config(dir.path()));

        std::fs::write(dir.path().join("package.json"), "{not json").unwrap();
        assert!(!read_auto_build_config(dir.path()));
    }

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

    // ── Phase 32 Phase 2 M2/M4: add_packages_to_manifest behavior ──────────

    fn write_manifest(path: &Path, value: &serde_json::Value) {
        std::fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    }

    fn read_manifest(path: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn add_packages_to_manifest_adds_to_dependencies_when_save_dev_false() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        add_packages_to_manifest(&pkg_path, &["react".to_string()], false, true).unwrap();

        let after = read_manifest(&pkg_path);
        assert!(after["dependencies"]["react"].is_string());
        assert!(after.get("devDependencies").is_none());
    }

    #[test]
    fn add_packages_to_manifest_adds_to_dev_dependencies_when_save_dev_true() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        add_packages_to_manifest(&pkg_path, &["vitest".to_string()], true, true).unwrap();

        let after = read_manifest(&pkg_path);
        assert!(after["devDependencies"]["vitest"].is_string());
        assert!(after.get("dependencies").is_none());
    }

    #[test]
    fn add_packages_to_manifest_preserves_existing_unrelated_entries() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(
            &pkg_path,
            &serde_json::json!({
                "name": "demo",
                "version": "1.0.0",
                "scripts": {"build": "tsup"},
                "dependencies": {"existing": "1.0.0"},
                "lpm": {"trustedDependencies": ["esbuild"]},
            }),
        );

        add_packages_to_manifest(&pkg_path, &["new-pkg".to_string()], false, true).unwrap();

        let after = read_manifest(&pkg_path);
        assert_eq!(after["name"], "demo");
        assert_eq!(after["version"], "1.0.0");
        assert_eq!(after["scripts"]["build"], "tsup");
        assert_eq!(after["dependencies"]["existing"], "1.0.0");
        assert_eq!(after["dependencies"]["new-pkg"], "*");
        assert_eq!(after["lpm"]["trustedDependencies"][0], "esbuild");
    }

    #[test]
    fn add_packages_to_manifest_handles_version_specs() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        add_packages_to_manifest(
            &pkg_path,
            &[
                "react@18.2.0".to_string(),
                "lodash@^4.17.0".to_string(),
                "no-version-spec".to_string(),
            ],
            false,
            true,
        )
        .unwrap();

        let after = read_manifest(&pkg_path);
        assert_eq!(after["dependencies"]["react"], "18.2.0");
        assert_eq!(after["dependencies"]["lodash"], "^4.17.0");
        assert_eq!(after["dependencies"]["no-version-spec"], "*");
    }

    #[test]
    fn add_packages_to_manifest_overwrites_existing_entry_with_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(
            &pkg_path,
            &serde_json::json!({
                "name": "demo",
                "dependencies": {"react": "17.0.0"},
            }),
        );

        add_packages_to_manifest(&pkg_path, &["react@18.2.0".to_string()], false, true).unwrap();

        let after = read_manifest(&pkg_path);
        assert_eq!(after["dependencies"]["react"], "18.2.0");
    }

    #[test]
    fn add_packages_to_manifest_errors_when_manifest_missing() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("does-not-exist").join("package.json");

        let result = add_packages_to_manifest(&absent, &["foo".to_string()], false, true);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no package.json"));
    }

    #[test]
    fn add_packages_to_manifest_errors_on_malformed_input_without_overwriting() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        std::fs::write(&pkg_path, "{not valid json").unwrap();
        let original = std::fs::read_to_string(&pkg_path).unwrap();

        let result = add_packages_to_manifest(&pkg_path, &["foo".to_string()], false, true);

        assert!(result.is_err(), "malformed manifest must error");
        // The corrupt file must be left unchanged
        assert_eq!(std::fs::read_to_string(&pkg_path).unwrap(), original);
    }

    #[test]
    fn add_packages_to_manifest_writes_atomic_pretty_json_with_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        write_manifest(&pkg_path, &serde_json::json!({"name": "demo"}));

        add_packages_to_manifest(&pkg_path, &["foo".to_string()], false, true).unwrap();

        let raw = std::fs::read_to_string(&pkg_path).unwrap();
        // Pretty-printed: contains indentation
        assert!(raw.contains("  \"dependencies\""));
        // Trailing newline
        assert!(raw.ends_with('\n'));
    }

    // ── Phase 2 audit fix #1: D2 migration hint on filtered install no-match ──

    /// Helper: real on-disk workspace fixture so resolve_install_targets can
    /// actually discover it.
    fn write_workspace_for_install_tests(
        root: &Path,
        members: &[(&str, &str)],
    ) {
        let workspace_globs: Vec<String> =
            members.iter().map(|(_, p)| (*p).to_string()).collect();
        let root_pkg = serde_json::json!({
            "name": "monorepo",
            "private": true,
            "workspaces": workspace_globs,
        });
        std::fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();
        for (name, path) in members {
            let dir = root.join(path);
            std::fs::create_dir_all(&dir).unwrap();
            let pkg = serde_json::json!({"name": name, "version": "0.0.0"});
            std::fs::write(
                dir.join("package.json"),
                serde_json::to_string_pretty(&pkg).unwrap(),
            )
            .unwrap();
        }
    }

    #[tokio::test]
    async fn run_install_filtered_add_no_match_with_fail_flag_includes_d2_hint_for_bare_names() {
        // Phase 2 audit regression: filtered install must surface the D2
        // substring → glob migration hint when --fail-if-no-match fires AND
        // a filter looks like a bare name.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_for_install_tests(dir.path(), &[("foo", "packages/foo")]);
        let client = lpm_registry::RegistryClient::new();

        let result = run_install_filtered_add(
            &client,
            dir.path(),
            &["react".to_string()],
            false,                       // save_dev
            &["app".to_string()],         // bare-name filter that matches nothing
            false,                       // workspace_root_flag
            true,                        // fail_if_no_match — required for the error path
            true,                        // json_output
            false,                       // allow_new
            false,                       // force
        )
        .await;

        assert!(result.is_err(), "fail_if_no_match must error on no match");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("D2"),
            "error must reference design decision D2, got: {err}"
        );
        assert!(
            err.contains("\"*app*\"") || err.contains("\"*/app\""),
            "error must suggest at least one glob form, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_install_filtered_add_no_match_for_glob_filter_does_not_emit_d2_hint() {
        // Negative case: glob filter is already migrated, no hint needed.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_for_install_tests(dir.path(), &[("foo", "packages/foo")]);
        let client = lpm_registry::RegistryClient::new();

        let result = run_install_filtered_add(
            &client,
            dir.path(),
            &["react".to_string()],
            false,
            &["nonexistent-*".to_string()],
            false,
            true,
            true,
            false,
            false,
        )
        .await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            !err.contains("D2"),
            "glob-only filter must NOT trigger the D2 hint, got: {err}"
        );
    }

    // ── Phase 2 audit fix: install_root must be the member dir, not workspace ──

    #[tokio::test]
    async fn run_install_filtered_add_mutates_targeted_member_manifest_on_fresh_workspace() {
        // GPT audit reproduction: filtered install on a workspace whose root
        // package.json has NO dependencies. Pre-fix this silently dropped
        // the install entirely because run_with_options was called with
        // project_dir=workspace_root, which has empty deps and short-circuits.
        //
        // This test asserts the manifest mutation lands at the targeted
        // member, which is the part of the install pipeline we can verify
        // without network. We can't run the actual install pipeline in
        // unit tests (it needs network), but the manifest mutation is the
        // first step of the workflow and is testable in isolation.
        let dir = tempfile::tempdir().unwrap();
        write_workspace_for_install_tests(
            dir.path(),
            &[("@test/app", "packages/app"), ("@test/core", "packages/core")],
        );

        // Verify the workspace root package.json has NO dependencies
        // (this is the precondition that triggered the bug).
        let root_pkg: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(
            root_pkg.get("dependencies").is_none(),
            "test precondition: workspace root must have no dependencies"
        );

        // Use the install_targets resolver directly — this avoids the
        // network-dependent run_with_options call and verifies the part
        // of the workflow that Phase 2 owns.
        let cwd = dir.path().join("packages").join("core");
        let targets = crate::commands::install_targets::resolve_install_targets(
            &cwd,
            &["@test/app".to_string()],
            false,
            true,
        )
        .unwrap();

        // CRITICAL: install root must be the member dir, not the workspace root
        assert_eq!(targets.member_manifests.len(), 1);
        let install_root =
            crate::commands::install_targets::install_root_for(&targets.member_manifests[0]);
        let expected = dir.path().join("packages").join("app");
        assert_eq!(
            install_root.canonicalize().unwrap(),
            expected.canonicalize().unwrap(),
            "install root for filtered install must be the member dir"
        );
        assert_ne!(
            install_root.canonicalize().unwrap(),
            dir.path().canonicalize().unwrap(),
            "regression: install root must NOT be the workspace root"
        );

        // Now mutate the manifest the way run_install_filtered_add would,
        // and verify the result lands at packages/app.
        add_packages_to_manifest(
            &targets.member_manifests[0],
            &["react@18.2.0".to_string()],
            false,
            true,
        )
        .unwrap();

        let app_pkg: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("packages/app/package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(app_pkg["dependencies"]["react"], "18.2.0");

        // Workspace root must remain unchanged
        let root_after: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert!(root_after.get("dependencies").is_none());
    }

    // ── Phase 2 audit fix #3 (workspace:^ resolver bug) — diagnostics + repro ──

    /// DIAGNOSTIC: empirically confirm what the resolver sees when a member's
    /// `package.json` declares a cross-member dep via `workspace:^`. This is
    /// the test that distinguished Hypothesis A (rewrite never runs) from
    /// Hypothesis B (rewrite runs and turns `workspace:^` into a concrete
    /// range that the resolver then fails to fetch from the registry).
    ///
    /// The pre-fix behavior was Hypothesis B: `resolve_workspace_protocol`
    /// rewrote `@test/core@workspace:^` to `@test/core@^1.5.0`, the resolver
    /// classified `@test/core` as an npm package (it doesn't start with
    /// `@lpm.dev/`), and the lookup 404'd against the npm upstream proxy.
    ///
    /// The post-fix behavior is "extracted before resolution": the workspace
    /// member is removed from the resolver's input HashMap entirely, and the
    /// install pipeline links it directly from its source dir instead.
    #[test]
    fn workspace_protocol_dep_is_extracted_before_resolver_sees_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Build a workspace where @test/app depends on @test/core via workspace:^
        // and @test/core has a concrete version (1.5.0). Mirrors the user repro.
        let root_pkg = serde_json::json!({
            "name": "monorepo",
            "private": true,
            "workspaces": ["packages/*"],
        });
        std::fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&root_pkg).unwrap(),
        )
        .unwrap();

        let app_dir = root.join("packages").join("app");
        let core_dir = root.join("packages").join("core");
        std::fs::create_dir_all(&app_dir).unwrap();
        std::fs::create_dir_all(&core_dir).unwrap();

        let app_pkg = serde_json::json!({
            "name": "@test/app",
            "version": "0.1.0",
            "dependencies": { "@test/core": "workspace:^" },
        });
        let core_pkg = serde_json::json!({
            "name": "@test/core",
            "version": "1.5.0",
        });
        std::fs::write(
            app_dir.join("package.json"),
            serde_json::to_string_pretty(&app_pkg).unwrap(),
        )
        .unwrap();
        std::fs::write(
            core_dir.join("package.json"),
            serde_json::to_string_pretty(&core_pkg).unwrap(),
        )
        .unwrap();

        // Reproduce the prefix of run_with_options exactly:
        let pkg = lpm_workspace::read_package_json(&app_dir.join("package.json")).unwrap();
        let mut deps = pkg.dependencies.clone();
        let workspace = lpm_workspace::discover_workspace(&app_dir).unwrap().unwrap();

        // Pre-fix: deps after `resolve_workspace_protocol` would contain
        // `{"@test/core": "^1.5.0"}` and be passed straight to the resolver,
        // which would call `get_npm_package_metadata("@test/core")` and 404.
        // Post-fix: `extract_workspace_protocol_deps` removes the member from
        // `deps` and returns it as a `WorkspaceMemberLink`.
        let extracted = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap();

        // The resolver-input HashMap must NOT contain @test/core anymore.
        assert!(
            !deps.contains_key("@test/core"),
            "post-fix: @test/core must be stripped from resolver input \
             (pre-fix it was `^1.5.0` and the resolver 404'd against npm)"
        );
        assert!(
            deps.is_empty(),
            "the only declared dep was a workspace member, deps must be empty after extraction"
        );

        // The extracted member metadata must point at the on-disk source dir
        // and the version from the member's own package.json.
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, "@test/core");
        assert_eq!(extracted[0].version, "1.5.0");
        assert_eq!(
            extracted[0].source_dir.canonicalize().unwrap(),
            core_dir.canonicalize().unwrap(),
        );
    }

    /// REGRESSION: Hypothesis-A negative test. Even though the bug turned out
    /// to be Hypothesis B, this case is still load-bearing — if a future
    /// refactor accidentally re-introduces a path where `discover_workspace`
    /// fails to walk up from a member dir, this test catches it. The
    /// member-dir → workspace-root walk MUST keep working for the
    /// `workspace:^` extraction to fire at all.
    #[test]
    fn discover_workspace_from_member_dir_finds_workspace_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[("@test/app", "packages/app"), ("@test/core", "packages/core")],
        );

        // Walking up from any member dir must find the workspace root.
        for member in &["packages/app", "packages/core"] {
            let member_dir = root.join(member);
            let ws = lpm_workspace::discover_workspace(&member_dir)
                .expect("discovery must not error")
                .expect("workspace root must be discoverable from member dir");
            assert_eq!(
                ws.root.canonicalize().unwrap(),
                root.canonicalize().unwrap(),
                "discover_workspace from {member} did not find the workspace root"
            );
        }
    }

    /// REGRESSION: full extraction round-trip on a workspace where two
    /// members reference each other AND the install root has a regular
    /// registry dep too. The extraction must:
    /// 1. Strip the workspace member dep from `deps`
    /// 2. Leave the registry dep in `deps`
    /// 3. Return exactly one `WorkspaceMemberLink` pointing at the right dir
    #[test]
    fn extract_workspace_protocol_deps_only_strips_workspace_protocol_entries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[("@test/app", "packages/app"), ("@test/core", "packages/core")],
        );

        // Manually rewrite @test/core's manifest with a real version,
        // and @test/app's manifest with both a registry dep AND a workspace dep.
        std::fs::write(
            root.join("packages/core/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/core",
                "version": "2.3.4",
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            root.join("packages/app/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/app",
                "version": "0.0.0",
                "dependencies": {
                    "@test/core": "workspace:^",
                    "react": "^18.0.0",
                },
            }))
            .unwrap(),
        )
        .unwrap();

        let app_dir = root.join("packages/app");
        let pkg = lpm_workspace::read_package_json(&app_dir.join("package.json")).unwrap();
        let mut deps = pkg.dependencies.clone();
        let workspace = lpm_workspace::discover_workspace(&app_dir).unwrap().unwrap();

        let extracted = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap();

        // Workspace member stripped, registry dep retained.
        assert!(!deps.contains_key("@test/core"));
        assert_eq!(deps.get("react").map(String::as_str), Some("^18.0.0"));
        assert_eq!(deps.len(), 1);

        // Extraction surfaces the member's source dir + version.
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].name, "@test/core");
        assert_eq!(extracted[0].version, "2.3.4");
        assert_eq!(
            extracted[0].source_dir.canonicalize().unwrap(),
            root.join("packages/core").canonicalize().unwrap(),
        );
    }

    /// REGRESSION: `workspace:` form variants are all handled. Pre-fix this
    /// would only have caught `workspace:^` because that's what the user repro
    /// used; post-fix the helper handles all forms.
    #[test]
    fn extract_workspace_protocol_deps_handles_all_workspace_protocol_forms() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[
                ("@test/star", "packages/star"),
                ("@test/caret", "packages/caret"),
                ("@test/tilde", "packages/tilde"),
                ("@test/exact", "packages/exact"),
                ("@test/passthrough", "packages/passthrough"),
                ("@test/host", "packages/host"),
            ],
        );
        // Every member needs a concrete version
        for name in [
            "star",
            "caret",
            "tilde",
            "exact",
            "passthrough",
        ] {
            std::fs::write(
                root.join(format!("packages/{name}/package.json")),
                serde_json::to_string_pretty(&serde_json::json!({
                    "name": format!("@test/{name}"),
                    "version": "1.0.0",
                }))
                .unwrap(),
            )
            .unwrap();
        }
        std::fs::write(
            root.join("packages/host/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/host",
                "version": "0.0.0",
                "dependencies": {
                    "@test/star": "workspace:*",
                    "@test/caret": "workspace:^",
                    "@test/tilde": "workspace:~",
                    "@test/exact": "workspace:1.0.0",
                    "@test/passthrough": "workspace:>=1.0.0",
                },
            }))
            .unwrap(),
        )
        .unwrap();

        let host_dir = root.join("packages/host");
        let pkg = lpm_workspace::read_package_json(&host_dir.join("package.json")).unwrap();
        let mut deps = pkg.dependencies.clone();
        let workspace = lpm_workspace::discover_workspace(&host_dir).unwrap().unwrap();

        let extracted = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap();

        assert!(
            deps.is_empty(),
            "all five workspace: deps must be stripped, deps={deps:?}"
        );
        assert_eq!(extracted.len(), 5, "all five forms must be extracted");
        let names: std::collections::HashSet<&str> =
            extracted.iter().map(|m| m.name.as_str()).collect();
        for n in [
            "@test/star",
            "@test/caret",
            "@test/tilde",
            "@test/exact",
            "@test/passthrough",
        ] {
            assert!(names.contains(n), "missing extracted member {n}");
        }
    }

    /// REGRESSION: a `workspace:` reference to an unknown member must hard
    /// error so users don't silently install nothing. Mirrors the validation
    /// `resolve_workspace_protocol` already enforces.
    #[test]
    fn extract_workspace_protocol_deps_errors_on_unknown_member() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(root, &[("@test/app", "packages/app")]);
        std::fs::write(
            root.join("packages/app/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/app",
                "version": "0.0.0",
                "dependencies": { "@test/missing": "workspace:^" },
            }))
            .unwrap(),
        )
        .unwrap();

        let app_dir = root.join("packages/app");
        let pkg = lpm_workspace::read_package_json(&app_dir.join("package.json")).unwrap();
        let mut deps = pkg.dependencies.clone();
        let workspace = lpm_workspace::discover_workspace(&app_dir).unwrap().unwrap();

        let err = extract_workspace_protocol_deps(&mut deps, &workspace).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("@test/missing"),
            "error must name the missing member, got: {msg}"
        );
        assert!(
            msg.contains("not a workspace member") || msg.contains("Available"),
            "error must explain what's wrong, got: {msg}"
        );
    }

    /// REGRESSION: when ALL declared deps are workspace members, the install
    /// pipeline must still link them. Pre-fix the empty-deps short-circuit at
    /// install.rs line ~172 would return early after extraction; post-fix the
    /// short-circuit is gated on "deps empty AND workspace member list empty".
    #[test]
    fn link_workspace_members_creates_node_modules_symlink_to_member_source_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[("@test/app", "packages/app"), ("@test/core", "packages/core")],
        );
        // Give @test/core a real version
        std::fs::write(
            root.join("packages/core/package.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "name": "@test/core",
                "version": "2.0.0",
            }))
            .unwrap(),
        )
        .unwrap();

        let app_dir = root.join("packages/app");
        let core_dir = root.join("packages/core");

        let members = vec![WorkspaceMemberLink {
            name: "@test/core".to_string(),
            version: "2.0.0".to_string(),
            source_dir: core_dir.clone(),
        }];

        let linked = link_workspace_members(&app_dir, &members).unwrap();
        assert_eq!(linked, 1);

        // node_modules/@test/core must exist and resolve back to packages/core
        let link_path = app_dir.join("node_modules").join("@test").join("core");
        assert!(
            link_path.symlink_metadata().is_ok(),
            "expected node_modules/@test/core to exist"
        );
        let resolved = std::fs::canonicalize(&link_path).unwrap();
        assert_eq!(
            resolved,
            core_dir.canonicalize().unwrap(),
            "symlink must resolve to the workspace member's source directory"
        );
    }

    /// REGRESSION: re-running `link_workspace_members` is idempotent and
    /// re-links over a stale symlink. The linker's stale-symlink cleanup
    /// pass would otherwise remove our workspace symlinks on every install
    /// (they're not in `direct_names`), so the post-link helper has to
    /// tolerate "the path already exists from a previous run" gracefully.
    #[test]
    fn link_workspace_members_is_idempotent_across_repeated_calls() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_workspace_for_install_tests(
            root,
            &[("@test/app", "packages/app"), ("@test/core", "packages/core")],
        );

        let app_dir = root.join("packages/app");
        let core_dir = root.join("packages/core");

        let members = vec![WorkspaceMemberLink {
            name: "@test/core".to_string(),
            version: "0.0.0".to_string(),
            source_dir: core_dir.clone(),
        }];

        link_workspace_members(&app_dir, &members).unwrap();
        link_workspace_members(&app_dir, &members).unwrap();
        link_workspace_members(&app_dir, &members).unwrap();

        let link_path = app_dir.join("node_modules").join("@test").join("core");
        let resolved = std::fs::canonicalize(&link_path).unwrap();
        assert_eq!(resolved, core_dir.canonicalize().unwrap());
    }
}
