use crate::doctor_catalog::{self, Severity};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use lpm_store::PackageStore;
use std::borrow::Cow;
use std::path::Path;
use std::time::Duration;

mod check;
mod config_file;
mod fix;
mod global;
mod install_fix;
mod local_sources;
mod lockfile;
mod manifest;
mod policy;
mod runtime;
mod sandbox;
mod script_policy;
mod sigstore;
mod storage;
#[cfg(test)]
mod test_support;
pub(in crate::commands) mod tooling;
mod tunnel;
mod workspace;

use self::check::{Check, FixTarget, format_doctor_issue_summary_colored};
use self::config_file::load_lpm_json;
use self::global::check_global_installs;
use self::local_sources::check_local_source_paths;
use self::lockfile::{
    DiagnosticLockfile, check_deps_in_sync, check_gitattributes_state, check_lockfile_state,
};
use self::manifest::check_manifest_compat;
use self::policy::check_policy_extensions;
use self::runtime::{
    get_system_bun_version, get_system_node_version, probe_system_version_if_unmanaged,
};
use self::script_policy::check_script_policy_surface_with_global;
use self::sigstore::check_sigstore_verify_posture;
use self::storage::{auth_storage_check, vault_storage_check};
use self::tooling::{
    check_plugins, check_typescript_setup, discover_installed_plugins, run_fmt_check,
    run_lint_check,
};
use self::tunnel::check_tunnel_domain_from_config;
use self::workspace::check_workspace;

const DIAGNOSTIC_NETWORK_DEADLINE: Duration = Duration::from_secs(5);

enum AuthProbe {
    Missing,
    Valid(&'static str),
    Invalid(&'static str),
    Unverified(String),
}

#[derive(serde::Serialize)]
struct DoctorCheckJson<'a> {
    code: &'static str,
    check: &'static str,
    passed: bool,
    severity: &'static str,
    detail: &'a str,
}

#[derive(serde::Serialize)]
struct DoctorOutputJson<'a> {
    success: bool,
    mode: &'static str,
    no_failures: bool,
    clean: bool,
    has_warnings: bool,
    checks: Vec<DoctorCheckJson<'a>>,
    passed: usize,
    failed: usize,
    warnings: usize,
    fixes_applied: &'a [String],
    fixes_failed: &'a [self::fix::FixFailure],
}

/// Render the canonical catalog inventory.
///
/// `lpm doctor list` is the documentation surface — it enumerates
/// every check `lpm doctor` can emit (CLI-side and workspace-owned
/// manifest-compat) along with description, when-fires, remediation,
/// possible severities, and auto-fix metadata. Stable shape: every
/// row carries a non-empty `code` field that downstream automation
/// can match on.
///
/// Filters:
/// - `code` selects a single entry by exact code match. An empty
///   result is treated as a user error (likely typo) and exits
///   non-zero — automation gating on a code shouldn't silently pass
///   when the code doesn't exist.
/// - `category` is a case-insensitive substring filter against the
///   catalog category label. Empty result is benign (substring
///   semantics) and exits zero with a stderr note.
///
/// `--json` returns the structured array; without it, the listing
/// is grouped by category and rendered for terminals.
pub fn list(
    json_output: bool,
    code_filter: Option<&str>,
    category_filter: Option<&str>,
) -> Result<(), LpmError> {
    let mut rows = doctor_catalog::all_entries();
    let code_exists = code_filter.is_none_or(|code| rows.iter().any(|row| row.code == code));

    if let Some(code) = code_filter {
        rows.retain(|r| r.code == code);
    }
    if let Some(cat) = category_filter {
        let needle = cat.to_lowercase();
        rows.retain(|r| r.category.as_str().to_lowercase().contains(needle.as_str()));
    }

    // `--code` is exact-match — an empty result almost always means
    // the user typo'd a code. Surface this as a hard error so
    // automation doesn't silently pass when the gating code doesn't
    // exist. The error propagates through the standard `LpmError`
    // path; in `--json` mode the outer handler wraps it in the
    // canonical `{success: false, error, error_code}` envelope, so
    // stdout stays a single valid JSON document either way.
    if let Some(code) = code_filter
        && !code_exists
    {
        return Err(LpmError::Script(format!(
            "no catalog entry matches code `{code}` — run `lpm doctor list` to see the full inventory",
        )));
    }

    if json_output {
        // Field-name parity with `lpm doctor --json`: the runtime
        // emission surface uses `check` for the human-readable label,
        // so the inventory surface uses the same key. Match on `code`
        // in automation; `check` is human-only.
        let entries: Vec<_> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "code": r.code,
                    "check": r.name,
                    "category": r.category.as_str(),
                    "tier": r.tier.as_str(),
                    "description": r.description,
                    "when_fires": r.when_fires,
                    "remediation": r.remediation,
                    "possible_severities": r.possible_severities,
                    "auto_fix": r.auto_fix,
                })
            })
            .collect();
        let output = serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "count": entries.len(),
            "entries": entries,
        }))
        .map_err(|e| LpmError::Script(format!("failed to serialize catalog: {e}")))?;
        println!("{output}");
        return Ok(());
    }

    if rows.is_empty() {
        eprintln!("No catalog entries matched the given filter.");
        return Ok(());
    }

    println!();
    println!(
        "  {} {} catalog entries",
        rows.len().to_string().bold(),
        "doctor".dimmed()
    );
    println!();

    let mut current_category: Option<doctor_catalog::Category> = None;
    for row in &rows {
        if Some(row.category) != current_category {
            current_category = Some(row.category);
            println!("  {}", row.category.as_str().bold().underline());
            println!();
        }
        let severities = row.possible_severities.join(", ");
        println!(
            "    {}  {}  {}",
            row.code.bold(),
            format!("[{severities}]").dimmed(),
            format!("(tier: {})", row.tier).dimmed(),
        );
        println!("      {}: {}", "name".dimmed(), row.name);
        println!("      {}", row.description);
        println!("      {} {}", "when:".dimmed(), row.when_fires);
        println!("      {} {}", "fix:".dimmed(), row.remediation);
        if let Some(auto) = row.auto_fix {
            println!("      {} {}", "auto-fix:".dimmed(), auto);
        }
        println!();
    }

    Ok(())
}

/// Health check pipeline.
///
/// Two execution tiers (orthogonal to category — see
/// [`crate::doctor_catalog::Tier`]):
///
/// - **Fast (default `lpm doctor`):** local-only "why is this project
///   broken right now?" pass. Zero network calls. Zero subprocess
///   spawns except `node --version` (2s-bounded) for runtime detection.
///   Covers global store accessibility, `package.json`, linker mode,
///   `node_modules` layout, lockfile health, deps sync, local
///   `file:` / `link:` source paths, `lpm.json` validity, Node
///   runtime readiness, and workspace cycle detection.
///
/// - **Full sweep (`lpm doctor --all`):** every catalog row. Adds
///   registry probe + `whoami`, tunnel ownership lookup, lint / fmt
///   subprocesses, TypeScript reachability, plugin update fetch,
///   global-install hygiene (manifest, PATH, shims, install roots),
///   sandbox probe, full manifest-compat sweep, and project-hygiene
///   rows (`.gitattributes` lockb marker, v2-store orphan stats).
///
/// `--fix` operates on whichever set actually emitted — fast-mode
/// `--fix` cannot repair rows it didn't check.
pub async fn run(
    client: &RegistryClient,
    registry_url: &str,
    project_dir: &Path,
    json_output: bool,
    all: bool,
    fix: bool,
    yes: bool,
) -> Result<(), LpmError> {
    let (workspace, workspace_discovery_error) =
        match lpm_workspace::discover_workspace(project_dir) {
            Ok(workspace) => (workspace.map(std::sync::Arc::new), None),
            Err(error) => (None, Some(error.to_string())),
        };
    crate::workspace_discovery_cache::scope_discovery(
        project_dir,
        workspace,
        run_inner(
            client,
            registry_url,
            project_dir,
            json_output,
            all,
            fix,
            yes,
            None,
            workspace_discovery_error.as_deref(),
        ),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_inner(
    client: &RegistryClient,
    registry_url: &str,
    project_dir: &Path,
    json_output: bool,
    all: bool,
    fix: bool,
    yes: bool,
    fix_report: Option<self::fix::FixReport>,
    workspace_discovery_error: Option<&str>,
) -> Result<(), LpmError> {
    let mut checks: Vec<Check> = Vec::new();
    let loaded_global_config = crate::commands::config::GlobalConfig::load_checked();
    let global_config_error = loaded_global_config.as_ref().err().map(ToString::to_string);
    let global_config =
        loaded_global_config.unwrap_or_else(|_| crate::commands::config::GlobalConfig::empty());
    let mut sweep_progress = if all && !json_output {
        Some(install_ui::spin("Running doctor --all checks"))
    } else {
        None
    };

    // Shared between the registry/auth probe (Extended) and the
    // tunnel block (Extended). Stays `false` on the fast path since
    // both consumers are gated behind `if all`.
    let mut auth_verified = false;

    let registry_auth_task = all.then(|| {
        let diagnostic_client = client.clone_with_config();
        let auth_source = diagnostic_client.auth_source_label();
        tokio::spawn(async move {
            tokio::join!(
                tokio::time::timeout(
                    DIAGNOSTIC_NETWORK_DEADLINE,
                    diagnostic_client.diagnostic_health_check_once()
                ),
                probe_auth(&diagnostic_client, auth_source)
            )
        })
    });
    let installed_plugins = all.then(|| std::sync::Arc::new(discover_installed_plugins()));
    let lint_task = installed_plugins.as_ref().map(|plugins| {
        let project = project_dir.to_path_buf();
        let plugins = std::sync::Arc::clone(plugins);
        tokio::task::spawn_blocking(move || run_lint_check(&project, &plugins))
    });
    let fmt_task = installed_plugins.as_ref().map(|plugins| {
        let project = project_dir.to_path_buf();
        let plugins = std::sync::Arc::clone(plugins);
        tokio::task::spawn_blocking(move || run_fmt_check(&project, &plugins))
    });
    let plugin_task = installed_plugins.as_ref().map(|plugins| {
        let plugins = std::sync::Arc::clone(plugins);
        tokio::spawn(async move { check_plugins(&plugins).await })
    });
    let global_task = all.then(|| tokio::task::spawn_blocking(check_global_installs));

    // === Infrastructure: registry + auth (Extended) ===
    //
    // Both probes touch the network. Skipped on the fast path —
    // default `lpm doctor` is local-only.
    if let Some(check) = auth_storage_check(client.diagnostic_auth_storage_status(registry_url)) {
        checks.push(check);
    }

    checks.push(vault_storage_check(lpm_vault::storage_backend()));
    checks.extend(check_policy_extensions(
        &global_config,
        global_config_error.as_deref(),
    ));

    // 3. Global store accessible?
    let store_result = check_store_accessibility();
    if let Ok(store_detail) = &store_result {
        checks.push(Check::pass(
            &doctor_catalog::GLOBAL_STORE_ACCESSIBLE,
            store_detail,
        ));
    } else {
        checks.push(Check::fail(
            &doctor_catalog::GLOBAL_STORE_INACCESSIBLE,
            store_result
                .as_ref()
                .expect_err("inaccessible store must carry an error"),
        ));
    }

    // === Project State ===

    // 4. package.json exists?
    let pkg_json_path = project_dir.join("package.json");
    let workspace = crate::workspace_discovery_cache::active_workspace(project_dir);
    let cached_package_manifest = workspace.as_ref().and_then(|workspace| {
        if workspace.root == project_dir {
            Some(&workspace.root_package)
        } else {
            workspace
                .members
                .iter()
                .find(|member| member.path == project_dir)
                .map(|member| &member.package)
        }
    });
    let package_manifest = match cached_package_manifest.map_or_else(
        || lpm_workspace::read_package_json(&pkg_json_path).map(Cow::Owned),
        |package| Ok(Cow::Borrowed(package)),
    ) {
        Ok(package) => {
            checks.push(Check::pass(&doctor_catalog::PACKAGE_JSON_PRESENT, "found"));
            Some(package)
        }
        Err(lpm_workspace::WorkspaceError::NotFound(_)) => {
            checks.push(Check::fail(
                &doctor_catalog::PACKAGE_JSON_MISSING,
                "not found — run: lpm init (or cd to your project root)",
            ));
            None
        }
        Err(error) => {
            checks.push(Check::fail(
                &doctor_catalog::PACKAGE_JSON_INVALID,
                &error.to_string(),
            ));
            None
        }
    };
    let package_manifest_valid = package_manifest.is_some();

    // 4.5. Resolved linker mode + source — surfaces "why is my linker
    // mode X?" so users running `lpm doctor` after the workspace-aware
    // default flip can see whether the result came from an explicit
    // override or auto-detection. Skipped silently when there's no
    // readable package.json (no manifest → no resolution to report);
    // the resolution-error path emits a fail anyway via the install
    // pipeline. Best-effort: any I/O / parse failure here downgrades
    // to a quiet skip rather than failing doctor.
    if let Some(pkg_parsed) = package_manifest.as_ref()
        && let Ok((mode, source)) = crate::linker_config::resolve_effective_linker_with_source(
            None,
            pkg_parsed,
            &global_config,
            project_dir,
        )
    {
        let mode_str = match mode {
            lpm_linker::LinkerMode::Isolated => "isolated",
            lpm_linker::LinkerMode::Hoisted => "hoisted",
        };
        checks.push(Check::pass(
            &doctor_catalog::LINKER_MODE_RESOLVED,
            &format!("{mode_str} (source: {})", source.as_str()),
        ));
    }

    // 5. node_modules intact?
    //
    // + hoisted-symmetry: predicate is layout-aware via
    // `LayoutPaths::install_appears_healthy()`. The variant in the
    // message tells the user which linker mode produced their tree
    // (isolated under `<project>/.lpm/wrappers/`, hoisted under
    // `<project>/.lpm/hoisted/metadata.json`), and the `Mixed` case
    // points the user at the convergence remediation.
    //
    // Migration-aware: when `needs_layout_migration()` is true, EITHER
    // the legacy isolated wrapper root (`node_modules/.lpm/`) or the
    // legacy hoisted metadata sidecar (`node_modules/.lpm-metadata.json`)
    // is populated and the corresponding new location is empty —
    // the user owes a `lpm install` to converge. The union predicate
    // covers both legacy layouts; we surface this as a warn so it
    // doesn't read as healthy.
    let layout = lpm_linker::LayoutPaths::for_project(project_dir);
    // Pass both virtual-store link roots so the health probe can
    // recognize a virtual-store install (no `.lpm/wrappers/` and no
    // `.lpm/hoisted/metadata.json`, but project-side `node_modules/`
    // symlinks pointing into the active global store). On a system
    // where `LpmRoot::from_env` fails (extremely rare; no $HOME and
    // no $LPM_HOME), the check degrades to legacy v1-only detection.
    let virtual_links_roots = lpm_common::LpmRoot::from_env()
        .ok()
        .map_or_else(Vec::new, |root| {
            vec![
                lpm_store::v2::StoreV2Paths::from_lpm_root(&root).links_root(),
                lpm_store::v2::StoreV2Paths::from_lpm_root_v3(&root).links_root(),
            ]
        });
    let virtual_links_root_refs = virtual_links_roots
        .iter()
        .map(std::path::PathBuf::as_path)
        .collect::<Vec<_>>();
    let node_modules = project_dir.join("node_modules");
    let node_modules_is_symlink = node_modules
        .symlink_metadata()
        .is_ok_and(|metadata| lpm_common::is_symlink_or_junction(&metadata));
    if node_modules_is_symlink {
        checks.push(Check::fail(
            &doctor_catalog::NODE_MODULES_SYMLINKED,
            "is a symlink or directory junction — run: lpm doctor --fix, then run: lpm install",
        ));
    } else if layout.needs_layout_migration() {
        checks.push(Check::warn(&doctor_catalog::NODE_MODULES_LEGACY_LAYOUT, "legacy wrapper layout detected — run: lpm install (one-time migration to .lpm/wrappers/)",));
    } else {
        match layout.install_appears_healthy_with_virtual_roots(&virtual_links_root_refs) {
            lpm_linker::InstallHealth::Healthy {
                layout: lpm_linker::LinkerLayout::Isolated,
            } => {
                checks.push(Check::pass(
                    &doctor_catalog::NODE_MODULES_ISOLATED_HEALTHY,
                    "exists with .lpm/wrappers store",
                ));
            }
            lpm_linker::InstallHealth::Healthy {
                layout: lpm_linker::LinkerLayout::Hoisted,
            } => {
                checks.push(Check::pass(
                    &doctor_catalog::NODE_MODULES_HOISTED_HEALTHY,
                    "exists with hoisted layout",
                ));
            }
            lpm_linker::InstallHealth::Healthy {
                layout: lpm_linker::LinkerLayout::Virtual,
            } => {
                checks.push(Check::pass(
                    &doctor_catalog::NODE_MODULES_VIRTUAL_HEALTHY,
                    "symlinks into the global virtual store",
                ));
            }
            lpm_linker::InstallHealth::Healthy {
                layout: lpm_linker::LinkerLayout::Mixed,
            } => {
                checks.push(Check::warn(
                    &doctor_catalog::NODE_MODULES_MIXED_LAYOUT,
                    "both isolated + hoisted state present — re-run: lpm install",
                ));
            }
            lpm_linker::InstallHealth::NodeModulesPresentButNoStore => {
                checks.push(Check::warn(
                    &doctor_catalog::NODE_MODULES_NO_STORE,
                    "exists but no .lpm store — run: lpm install",
                ));
            }
            lpm_linker::InstallHealth::NoNodeModules => {
                checks.push(Check::fail(
                    &doctor_catalog::NODE_MODULES_MISSING,
                    "not found — run: lpm install",
                ));
            }
        }
    }

    // === Virtual-store orphan stats (Extended) ===
    //
    // (preplan). Cheap but cross-project
    // hygiene rather than core breakage — only surface under `--all`.
    // Walks v2 and v3 `.lpm-link-meta.json` sidecars
    // + the registered-projects set, surfaces a count of orphans not
    // reachable from any project.
    if all && let Ok(lpm_root) = lpm_common::LpmRoot::from_env() {
        let mut orphan_links = 0usize;
        let mut orphan_objects = 0usize;
        let mut analysis_unavailable = None;
        let stores = [
            lpm_store::v2::Store::from_lpm_root_for_version(&lpm_root, lpm_store::StoreVersion::V2),
            lpm_store::v2::Store::from_lpm_root_for_version(&lpm_root, lpm_store::StoreVersion::V3),
        ];
        match crate::commands::cache_prune::compute_prune_stats_for_stores(&lpm_root, &stores) {
            Ok(stats_by_store) => {
                for stats in stats_by_store {
                    match stats.analysis {
                        crate::commands::cache_prune::PruneAnalysis::Available => {
                            orphan_links += stats.link_entries_orphaned;
                            orphan_objects += stats.object_entries_orphaned;
                        }
                        crate::commands::cache_prune::PruneAnalysis::RegistryMissing => {
                            analysis_unavailable.get_or_insert_with(|| {
                                "known-projects registry is missing; reachability is unknown"
                                    .to_string()
                            });
                        }
                        crate::commands::cache_prune::PruneAnalysis::RegistryCorrupt(reason) => {
                            analysis_unavailable.get_or_insert_with(|| {
                                format!("known-projects registry is corrupt: {reason}")
                            });
                        }
                    }
                }
            }
            Err(error) => {
                analysis_unavailable.get_or_insert_with(|| format!("store scan failed: {error}"));
            }
        }
        if let Some(reason) = analysis_unavailable {
            checks.push(Check::warn(
                &doctor_catalog::STORE_ORPHAN_ANALYSIS_UNAVAILABLE,
                &reason,
            ));
        } else {
            if orphan_links == 0 && orphan_objects == 0 {
                checks.push(Check::pass(&doctor_catalog::V2_STORE_ORPHANS, "no orphans"));
            } else {
                checks.push(Check::warn(
                    &doctor_catalog::V2_STORE_ORPHANS,
                    &format!(
                        "{orphan_links} link orphan{} + {orphan_objects} object orphan{}; \
                         run: lpm cache prune --apply",
                        if orphan_links == 1 { "" } else { "s" },
                        if orphan_objects == 1 { "" } else { "s" },
                    ),
                ));
            }
        }
    }

    // 6. Lockfile? (Fast — load-bearing for install)
    let diagnostic_lockfile = DiagnosticLockfile::load(project_dir);
    checks.extend(check_lockfile_state(&diagnostic_lockfile));

    // 6b. .gitattributes hygiene (Extended) — git-side correctness for
    // the binary lockfile, not a runtime-install gate.
    if all {
        checks.extend(check_gitattributes_state(project_dir, &diagnostic_lockfile));
    }

    // 6c. Dependencies in sync? (lockfile vs package.json)
    if let Some(package_manifest) = package_manifest.as_ref()
        && let Some(sync_check) = check_deps_in_sync(package_manifest, &diagnostic_lockfile)
    {
        checks.push(sync_check);
    }

    // 6d. file:/link: source health.
    // Reports broken paths, missing package.json, exotic file types
    // — anything that would cause a runtime install error users
    // could pre-detect.
    if package_manifest_valid {
        checks.extend(check_local_source_paths(
            project_dir,
            package_manifest
                .as_deref()
                .expect("valid package manifest was checked above"),
        ));
    }

    // === lpm.json Validation ===

    // 7. Validate lpm.json (if exists)
    let mut diagnostic_lpm_json = load_lpm_json(project_dir);
    if let Some(lpm_json_check) = diagnostic_lpm_json.check.take() {
        checks.push(lpm_json_check);
    }

    // === Manifest compatibility (Extended) ===
    //
    // Surfaces every issue from
    // [`lpm_workspace::PackageJson::manifest_compat_issues`] as its own
    // `Check::warn` entry with the issue's stable code. This is the
    // structured surface automation pipelines pull instead of the
    // stderr warnings emitted by `engine_check::enforce` — the same
    // detector backs both, so the two views can never disagree.
    //
    // Behind `--all`: the pnpm-drift / engines-ignored rows describe
    // semantic gaps with adjacent package managers, not breakage of
    // the current install — outside the default fast-mode scope.
    //
    // Requires a parsed `package.json`; we already guarded above that
    // it exists. Re-uses the workspace discovery so member-dir
    // invocations gate against the workspace root manifest, matching
    // the engine-check semantics (root manifest is the gate).
    if all && package_manifest_valid {
        let root_package = workspace
            .as_ref()
            .map_or_else(
                || package_manifest.as_deref(),
                |workspace| Some(&workspace.root_package),
            )
            .expect("valid package manifest was checked above");
        checks.extend(check_manifest_compat(root_package));
    }

    // === Runtime ===

    // 8. Node.js version
    let detected = lpm_runtime::detect::detect_node_version_with_lpm_json_spec(
        project_dir,
        diagnostic_lpm_json.node_spec(),
    )?;
    let managed_versions = lpm_runtime::node::list_installed().unwrap_or_default();
    let matched_managed_node = detected.as_ref().and_then(|detected| {
        lpm_runtime::node::find_matching_installed(&detected.spec, &managed_versions)
    });
    let system_node_version =
        probe_system_version_if_unmanaged(matched_managed_node.as_deref(), || {
            get_system_node_version(project_dir)
        });
    let effective_node_version = matched_managed_node
        .as_deref()
        .or(system_node_version.as_deref());
    let effective_source = if matched_managed_node.is_some() {
        "managed runtime"
    } else {
        "system PATH"
    };
    let effective_version = effective_node_version.map(|version| format!("v{version}"));

    if package_manifest_valid
        && let Some(requirement) =
            crate::engine_check::resolve_root_node_engine_requirement_from_package(
                workspace
                    .as_ref()
                    .map_or_else(
                        || package_manifest.as_deref(),
                        |workspace| Some(&workspace.root_package),
                    )
                    .expect("valid package manifest was checked above"),
                &global_config,
            )
        && let Some(actual) = effective_node_version
    {
        let source = effective_source;
        match crate::engine_check::version_satisfies(&requirement.required, actual) {
            Ok(true) => checks.push(Check::pass(
                &doctor_catalog::NODE_ENGINE_COMPATIBLE,
                &format!(
                    "v{actual} from {source} satisfies package.json > engines.node {}",
                    requirement.required
                ),
            )),
            Ok(false) => {
                let detail = format!(
                    "v{actual} from {source} does not satisfy package.json > engines.node {}",
                    requirement.required
                );
                if requirement.engine_strict {
                    checks.push(Check::fail(&doctor_catalog::NODE_ENGINE_MISMATCH, &detail));
                } else {
                    checks.push(Check::warn(
                        &doctor_catalog::NODE_ENGINE_MISMATCH,
                        &format!("{detail} (engine-strict disabled, ignoring)"),
                    ));
                }
            }
            Err(error) => {
                let detail = format!(
                    "could not validate package.json > engines.node {} against v{actual} from {source}: {error}",
                    requirement.required
                );
                if requirement.engine_strict {
                    checks.push(Check::fail(&doctor_catalog::NODE_ENGINE_MISMATCH, &detail));
                } else {
                    checks.push(Check::warn(
                        &doctor_catalog::NODE_ENGINE_MISMATCH,
                        &format!("{detail} (engine-strict disabled, ignoring)"),
                    ));
                }
            }
        }
    }

    if let Some(ref det) = detected {
        let spec = &det.spec;
        let matched_managed = matched_managed_node;

        if let Some(ver) = matched_managed {
            checks.push(Check::pass(
                &doctor_catalog::NODE_MANAGED_MATCH,
                &format!("v{ver} (managed, from {})", det.source_label()),
            ));
        } else if let Some(sys) = &effective_version {
            checks.push(Check::warn_with_fix_target(
                &doctor_catalog::NODE_PINNED_UNMET,
                &format!(
                    "{sys} (system PATH) — pinned {spec} from {} not installed. Run: lpm use node@{spec}",
                    det.source_label()
                ),
                FixTarget::NodeSpec(spec.to_string()),
            ));
        } else {
            checks.push(Check::fail_with_fix_target(
                &doctor_catalog::NODE_MISSING_PINNED,
                &format!(
                    "not found — pinned {spec} from {}. Run: lpm use node@{spec}",
                    det.source_label()
                ),
                FixTarget::NodeSpec(spec.to_string()),
            ));
        }
    } else {
        if let Some(v) = effective_version {
            checks.push(Check::pass(
                &doctor_catalog::NODE_SYSTEM_UNPINNED,
                &format!("{v} (system PATH, no version pinned)"),
            ));
        } else {
            checks.push(Check::fail_with_fix_target(
                &doctor_catalog::NODE_MISSING_UNPINNED,
                "not found — run: lpm use node@22",
                FixTarget::NodeSpec("22".into()),
            ));
        }
    }

    if let Some(det) =
        lpm_runtime::detect::detect_bun_version_with_lpm_json_spec(diagnostic_lpm_json.bun_spec())
    {
        let managed_versions = lpm_runtime::bun::list_installed().unwrap_or_default();
        let spec = &det.spec;
        let matched_managed = lpm_runtime::bun::find_matching_installed(spec, &managed_versions);
        let system_bun = probe_system_version_if_unmanaged(matched_managed.as_deref(), || {
            get_system_bun_version(project_dir)
        });

        if let Some(ver) = matched_managed {
            checks.push(Check::pass(
                &doctor_catalog::BUN_MANAGED_MATCH,
                &format!("{ver} (managed, from {})", det.source),
            ));
        } else if let Some(sys) = &system_bun {
            checks.push(Check::warn_with_fix_target(
                &doctor_catalog::BUN_PINNED_UNMET,
                &format!(
                    "{sys} (system) — pinned {spec} from {} not installed. Run: lpm use bun@{spec}",
                    det.source
                ),
                FixTarget::BunSpec(spec.clone()),
            ));
        } else {
            checks.push(Check::fail_with_fix_target(
                &doctor_catalog::BUN_MISSING_PINNED,
                &format!(
                    "not found — pinned {spec} from {}. Run: lpm use bun@{spec}",
                    det.source
                ),
                FixTarget::BunSpec(spec.clone()),
            ));
        }
    }

    if let Some(task) = registry_auth_task {
        let display_registry_url = install_ui::safe_url_origin(registry_url);
        let mut infrastructure_checks = Vec::with_capacity(2);
        match task.await {
            Ok((registry_result, auth_result)) => {
                let registry_ok = registry_result.is_ok_and(|result| result.unwrap_or(false));
                if registry_ok {
                    infrastructure_checks.push(Check::pass(
                        &doctor_catalog::REGISTRY_REACHABLE,
                        &display_registry_url,
                    ));
                } else {
                    infrastructure_checks.push(Check::fail(
                        &doctor_catalog::REGISTRY_UNREACHABLE,
                        &format!(
                            "{display_registry_url} — unreachable. Check your network or try again later"
                        ),
                    ));
                }
                match auth_result {
                    AuthProbe::Valid(source) => {
                        auth_verified = true;
                        infrastructure_checks.push(Check::pass(
                            &doctor_catalog::AUTH_VALID,
                            &format!("valid token from {source}"),
                        ));
                    }
                    AuthProbe::Invalid(source) => infrastructure_checks.push(Check::fail(
                        &doctor_catalog::AUTH_INVALID,
                        &format!("token from {source} was rejected — run: lpm login"),
                    )),
                    AuthProbe::Missing => infrastructure_checks.push(Check::fail(
                        &doctor_catalog::AUTH_MISSING,
                        "no token — run: lpm login",
                    )),
                    AuthProbe::Unverified(error) => infrastructure_checks
                        .push(Check::warn(&doctor_catalog::AUTH_UNVERIFIED, &error)),
                }
            }
            Err(error) => {
                infrastructure_checks.push(Check::fail(
                    &doctor_catalog::REGISTRY_UNREACHABLE,
                    &format!("{display_registry_url} — diagnostic worker failed: {error}"),
                ));
                infrastructure_checks.push(Check::warn(
                    &doctor_catalog::AUTH_UNVERIFIED,
                    &format!("authentication diagnostic worker failed: {error}"),
                ));
            }
        }
        checks.splice(0..0, infrastructure_checks);
    }

    // === Tunnel + Code Quality + TypeScript + Plugins ===
    if all {
        let typescript_checks = package_manifest.as_ref().map_or_else(Vec::new, |package| {
            check_typescript_setup(project_dir, package, workspace.as_deref())
        });

        let tunnel_future = check_tunnel_domain_from_config(
            diagnostic_lpm_json.config.as_ref(),
            client,
            auth_verified,
        );
        let (tunnel_checks, plugin_result, lint_result, fmt_result) = tokio::join!(
            tunnel_future,
            plugin_task.expect("plugin task exists in all mode"),
            lint_task.expect("lint task exists in all mode"),
            fmt_task.expect("format task exists in all mode"),
        );

        checks.extend(tunnel_checks);
        match lint_result {
            Ok(Some(check)) => checks.push(check),
            Ok(None) => {}
            Err(error) => checks.push(Check::warn(
                &doctor_catalog::LINT_PROBE_FAILED,
                &format!("lint diagnostic worker failed: {error}"),
            )),
        }
        match fmt_result {
            Ok(Some(check)) => checks.push(check),
            Ok(None) => {}
            Err(error) => checks.push(Check::warn(
                &doctor_catalog::FMT_PROBE_FAILED,
                &format!("format diagnostic worker failed: {error}"),
            )),
        }
        checks.extend(typescript_checks);
        match plugin_result {
            Ok(plugin_checks) => checks.extend(plugin_checks),
            Err(error) => checks.push(Check::warn(
                &doctor_catalog::PLUGIN_UPDATE_CHECK_FAILED,
                &format!("plugin diagnostic worker failed: {error}"),
            )),
        }
    }

    // === Workspace ===

    // 13. Workspace health
    if package_manifest_valid
        && let Some(ws_check) = check_workspace(project_dir, workspace_discovery_error)
    {
        checks.push(ws_check);
    }

    // === Global installs (Extended) ===
    //
    // Four checks, all gated on the existence of `~/.lpm/global/`:
    //
    //   14. Manifest validity — reads + structurally validates it
    //   15. PATH presence — `~/.lpm/bin/` on $PATH
    //   16. Orphaned bin shims — files in bin_dir without a manifest owner
    //   17. Install-root consistency — every manifest entry's install root
    //                                  exists AND carries a ready marker
    //
    // Behind `--all`: these describe global-install hygiene, not
    // project breakage, and the per-platform PATH probe is host
    // state rather than current-directory state.
    if all {
        match global_task.expect("global task exists in all mode").await {
            Ok(global_checks) => checks.extend(global_checks),
            Err(error) => checks.push(Check::warn(
                &doctor_catalog::GLOBAL_MANIFEST_CORRUPT,
                &format!("global diagnostic worker failed: {error}"),
            )),
        }
    }

    // Sigstore provenance posture (Fast) — surfaces the resolved
    // `EnforceMode` (env > [sigstore].verify > default) so an
    // operator who flipped the knob once and forgot doesn't fly
    // blind. Fast-tier: one config-file read, no network.
    checks.push(check_sigstore_verify_posture(&global_config));

    // === — Script policy + sandbox (Extended) ===
    //
    //   18. Sandbox availability — probe the per-platform backend.
    //   19. Script-policy scope boundary — project installs only in 46.0;
    //                                      globals ship with     //
    // Behind `--all`: sandbox + policy diagnostics report on host
    // capabilities (kernel version, helper availability) rather than
    // current-project breakage.
    if all {
        for check in
            check_script_policy_surface_with_global(&global_config, package_manifest.as_deref())
        {
            checks.push(check);
        }
    }

    if let Some(progress) = sweep_progress.take() {
        progress.settle();
    }

    if fix && self::fix::confirm_before_apply(&checks, json_output, yes)? {
        let report = self::fix::apply(&checks, client, project_dir, json_output).await;
        return Box::pin(run_inner(
            client,
            registry_url,
            project_dir,
            json_output,
            all,
            false,
            true,
            Some(report),
            workspace_discovery_error,
        ))
        .await;
    }
    let fix_report = fix_report.unwrap_or_default();
    let fix_failed = !fix_report.failed.is_empty();

    // Tier-leak tripwire: in fast mode, every emitted check MUST
    // carry `Tier::Fast` — block-level gates above are the source of
    // truth, and this catches a future refactor that emits an
    // Extended-tagged row from a Fast block by mistake.
    #[cfg(debug_assertions)]
    if !all {
        for c in &checks {
            debug_assert!(
                matches!(c.entry.tier, doctor_catalog::Tier::Fast),
                "fast-mode emission leak: code `{}` (tier {:?}) escaped \
                 from an Extended-tier block. Add the block's `if all` \
                 gate or move the code to `Tier::Fast` in the catalog.",
                c.code(),
                c.entry.tier,
            );
        }
    }

    // === Output (after fixes so JSON includes fixes_applied) ===

    let mode_str = if all { "all" } else { "fast" };

    if json_output {
        let mut results = Vec::with_capacity(checks.len());
        let mut passed_count = 0usize;
        let mut warning_count = 0usize;
        for check in &checks {
            passed_count += usize::from(check.passed);
            warning_count += usize::from(matches!(check.severity, Severity::Warn));
            results.push(DoctorCheckJson {
                code: check.code(),
                check: check.name(),
                passed: check.passed,
                severity: check.severity.as_str(),
                detail: &check.detail,
            });
        }
        let failed_count = checks.len() - passed_count;
        let no_failures = failed_count == 0;
        let has_warnings = warning_count != 0;
        let clean = no_failures && !has_warnings;
        let payload = DoctorOutputJson {
            success: true,
            mode: mode_str,
            no_failures,
            clean,
            has_warnings,
            checks: results,
            passed: passed_count,
            failed: failed_count,
            warnings: warning_count,
            fixes_applied: &fix_report.applied,
            fixes_failed: &fix_report.failed,
        };
        let estimated_detail_bytes = checks
            .iter()
            .map(|check| check.detail.len())
            .fold(0usize, usize::saturating_add);
        let mut output = Vec::with_capacity(
            estimated_detail_bytes.saturating_add(checks.len().saturating_mul(160)),
        );
        serde_json::to_writer_pretty(&mut output, &payload)
            .map_err(|e| LpmError::Script(format!("failed to serialize doctor output: {e}")))?;
        output.push(b'\n');
        use std::io::Write as _;
        std::io::stdout().lock().write_all(&output)?;
    } else {
        let failed = checks.iter().filter(|c| !c.passed).count();
        let warned = checks
            .iter()
            .filter(|c| matches!(c.severity, Severity::Warn))
            .count();
        let total = checks.len();

        // Fast-mode renderer shaping: ALWAYS suppress pass rows
        // except `LINKER_MODE_RESOLVED`, whether or not the run is
        // clean. On a broken project the user wants the fail / warn
        // rows visible on top, not buried beneath a wall of healthy
        // passes; on a clean project the short summary plus the
        // linker-mode breadcrumb is all the context that matters.
        // Linker mode survives the squelch because it explains
        // "why is my install hoisted vs isolated?" — frequently the
        // first thing users want to confirm. Position is preserved
        // (emission order), so the linker-mode row sits near the top
        // of the output as context BEFORE the broken rows below it.
        // `--all` keeps today's "render every row in emission order"
        // behavior — the full sweep already groups related rows
        // (Infrastructure → Project → Runtime → Tunnel → ...).
        let visible_checks: Vec<_> = checks
            .iter()
            .filter(|check| {
                all || !matches!(check.severity, Severity::Pass)
                    || check.code() == doctor_catalog::LINKER_MODE_RESOLVED.code
                    || check.code() == doctor_catalog::POLICY_EXTENSIONS_CONFIGURED.code
            })
            .collect();
        let name_width = visible_checks
            .iter()
            .map(|check| check.name().len())
            .max()
            .unwrap_or(0);

        println!();
        for check in visible_checks {
            let icon = match check.severity {
                Severity::Pass => "✓".green().to_string(),
                Severity::Fail => "✗".red().to_string(),
                Severity::Warn => "!".yellow().to_string(),
            };
            println!(
                "  {icon} {:<name_width$} {}",
                check.name(),
                install_ui::dim(&check.detail)
            );
        }
        println!();

        if failed == 0 && warned == 0 {
            println!(
                "  {} All {} checks passed",
                "✓".green(),
                install_ui::green(&total.to_string())
            );
            if !all {
                println!(
                    "\n  Run {} for registry, auth, tunnel, tooling, plugin, global,\n  \
                     sandbox, and full manifest-compat diagnostics.",
                    "lpm doctor --all".bold()
                );
            }
        } else if failed == 0 {
            println!(
                "  {} doctor found {}",
                "!".yellow(),
                format_doctor_issue_summary_colored(0, warned)
            );
        } else {
            println!(
                "  {} doctor found {}",
                "✗".red(),
                format_doctor_issue_summary_colored(failed, warned)
            );
        }
        println!();
    }

    // Exit code 1 when any check has hard failures (not warnings)
    let has_failures = checks.iter().any(|c| !c.passed) || fix_failed;
    if has_failures {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

fn check_store_accessibility() -> Result<String, String> {
    let store = PackageStore::default_location().map_err(|error| error.to_string())?;
    let root = store.root();
    match root.symlink_metadata() {
        Ok(metadata) if lpm_common::is_symlink_or_junction(&metadata) => Err(format!(
            "{} is a symlink or directory junction",
            root.display()
        )),
        Ok(metadata) if !metadata.is_dir() => Err(format!("{} is not a directory", root.display())),
        Ok(_) => std::fs::read_dir(root)
            .map(|_| root.display().to_string())
            .map_err(|error| format!("cannot read {}: {error}", root.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = root
                .parent()
                .ok_or_else(|| format!("{} has no parent directory", root.display()))?;
            std::fs::read_dir(parent)
                .map(|_| format!("{} (not created yet; parent is accessible)", root.display()))
                .map_err(|parent_error| {
                    format!("cannot access {}: {parent_error}", parent.display())
                })
        }
        Err(error) => Err(format!("cannot inspect {}: {error}", root.display())),
    }
}

async fn probe_auth(
    client: &RegistryClient,
    source: Result<Option<&'static str>, LpmError>,
) -> AuthProbe {
    let source = match source {
        Ok(Some(source)) => source,
        Ok(None) => return AuthProbe::Missing,
        Err(error) => return AuthProbe::Unverified(error.to_string()),
    };
    match tokio::time::timeout(DIAGNOSTIC_NETWORK_DEADLINE, client.whoami()).await {
        Ok(Ok(_)) => AuthProbe::Valid(source),
        Ok(Err(LpmError::AuthRequired | LpmError::Forbidden(_))) => AuthProbe::Invalid(source),
        Ok(Err(error)) => AuthProbe::Unverified(format!(
            "token from {source} could not be verified: {error}"
        )),
        Err(_) => AuthProbe::Unverified(format!(
            "token from {source} could not be verified within {} seconds",
            DIAGNOSTIC_NETWORK_DEADLINE.as_secs()
        )),
    }
}

fn render_autofix_failed(action: &str, error: &impl std::fmt::Display) {
    let error = error.to_string();
    install_ui::failed_untrusted(&format!(
        "{} failed: {}",
        lpm_common::sanitize_terminal_inline(action),
        lpm_common::sanitize_terminal_inline(&error)
    ));
}

fn replace_project_node_modules_link(project_dir: &Path) -> Result<(), LpmError> {
    let node_modules = project_dir.join("node_modules");
    lpm_common::remove_symlink_or_junction_entry(&node_modules).map_err(|error| {
        LpmError::Io(std::io::Error::new(
            error.kind(),
            format!(
                "failed to remove the project node_modules link at {}: {error}",
                node_modules.display()
            ),
        ))
    })?;
    lpm_linker::ensure_project_node_modules(project_dir)
}
