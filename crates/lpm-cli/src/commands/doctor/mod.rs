use crate::doctor_catalog::{self, Severity};
use crate::{auth, install_ui};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use lpm_store::PackageStore;
use std::path::Path;

mod check;
mod config_file;
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
mod tooling;
mod tunnel;
mod workspace;

use self::check::{Check, format_doctor_issue_summary_colored};
use self::config_file::validate_lpm_json;
use self::global::check_global_installs;
use self::install_fix::run_doctor_install;
use self::local_sources::check_local_source_paths;
use self::lockfile::{
    check_deps_in_sync, check_gitattributes_state, check_lockfile_state, fix_binary_lockfile,
    fix_gitattributes,
};
use self::manifest::check_manifest_compat;
use self::policy::check_policy_extensions;
use self::runtime::{extract_node_spec_from_detail, get_system_bun_version};
use self::script_policy::check_script_policy_surface;
use self::sigstore::check_sigstore_verify_posture;
use self::storage::{auth_storage_check, vault_storage_check};
use self::tooling::{check_plugins, check_typescript_setup, run_fmt_check, run_lint_check};
use self::tunnel::check_tunnel_domain;
use self::workspace::check_workspace;

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
        && rows.is_empty()
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
    _yes: bool,
) -> Result<(), LpmError> {
    let mut checks: Vec<Check> = Vec::new();
    let mut fixes_applied: Vec<String> = Vec::new();
    let mut sweep_progress = if all && !json_output {
        Some(install_ui::spin("Running doctor --all checks"))
    } else {
        None
    };

    // Shared between the registry/auth probe (Extended) and the
    // tunnel block (Extended). Stays `false` on the fast path since
    // both consumers are gated behind `if all`.
    let mut token_exists = false;

    // === Infrastructure: registry + auth (Extended) ===
    //
    // Both probes touch the network. Skipped on the fast path —
    // default `lpm doctor` is local-only.
    if all {
        token_exists = auth::get_token(registry_url).is_some();
        let (registry_result, auth_result) = tokio::join!(client.health_check(), async {
            if token_exists {
                client.whoami().await.is_ok()
            } else {
                false
            }
        });

        // 1. Registry reachable?
        let registry_ok = registry_result.unwrap_or(false);
        if registry_ok {
            checks.push(Check::pass(
                &doctor_catalog::REGISTRY_REACHABLE,
                registry_url,
            ));
        } else {
            checks.push(Check::fail(
                &doctor_catalog::REGISTRY_UNREACHABLE,
                &format!("{registry_url} — unreachable. Check your network or try again later"),
            ));
        }

        // 2. Auth token valid?
        if auth_result {
            checks.push(Check::pass(&doctor_catalog::AUTH_VALID, "valid token"));
        } else if token_exists {
            checks.push(Check::fail(
                &doctor_catalog::AUTH_INVALID,
                "token exists but invalid — run: lpm login",
            ));
        } else {
            checks.push(Check::fail(
                &doctor_catalog::AUTH_MISSING,
                "no token — run: lpm login",
            ));
        }
    }

    if let Some(check) = auth_storage_check(auth::auth_storage_status(registry_url)) {
        checks.push(check);
    }

    checks.push(vault_storage_check(lpm_vault::storage_backend()));
    checks.extend(check_policy_extensions());

    // 3. Global store accessible?
    let store_result = PackageStore::default_location();
    let store_ok = store_result.is_ok();
    let store_detail = store_result.map_or_else(
        |_| "inaccessible".into(),
        |s| s.root().display().to_string(),
    );
    if store_ok {
        checks.push(Check::pass(
            &doctor_catalog::GLOBAL_STORE_ACCESSIBLE,
            &store_detail,
        ));
    } else {
        checks.push(Check::fail(
            &doctor_catalog::GLOBAL_STORE_INACCESSIBLE,
            &store_detail,
        ));
    }

    // === Project State ===

    // 4. package.json exists?
    let pkg_json_path = project_dir.join("package.json");
    if pkg_json_path.exists() {
        checks.push(Check::pass(&doctor_catalog::PACKAGE_JSON_PRESENT, "found"));
    } else {
        checks.push(Check::fail(
            &doctor_catalog::PACKAGE_JSON_MISSING,
            "not found — run: lpm init (or cd to your project root)",
        ));
    }

    // 4.5. Resolved linker mode + source — surfaces "why is my linker
    // mode X?" so users running `lpm doctor` after the workspace-aware
    // default flip can see whether the result came from an explicit
    // override or auto-detection. Skipped silently when there's no
    // readable package.json (no manifest → no resolution to report);
    // the resolution-error path emits a fail anyway via the install
    // pipeline. Best-effort: any I/O / parse failure here downgrades
    // to a quiet skip rather than failing doctor.
    if let Ok(pkg_content) =
        lpm_common::read_text_file_capped(&pkg_json_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
        && let Ok(pkg_parsed) = serde_json::from_str::<lpm_workspace::PackageJson>(&pkg_content)
    {
        let cfg = crate::commands::config::GlobalConfig::load();
        if let Ok((mode, source)) = crate::linker_config::resolve_effective_linker_with_source(
            None,
            &pkg_parsed,
            &cfg,
            project_dir,
        ) {
            let mode_str = match mode {
                lpm_linker::LinkerMode::Isolated => "isolated",
                lpm_linker::LinkerMode::Hoisted => "hoisted",
            };
            checks.push(Check::pass(
                &doctor_catalog::LINKER_MODE_RESOLVED,
                &format!("{mode_str} (source: {})", source.as_str()),
            ));
        }
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
    if layout.needs_layout_migration() {
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
        let mut orphan_bytes = 0u64;
        let mut plans_valid = true;
        for version in [lpm_store::StoreVersion::V2, lpm_store::StoreVersion::V3] {
            let store = lpm_store::v2::Store::from_lpm_root_for_version(&lpm_root, version);
            match crate::commands::cache_prune::compute_prune_plan(
                &lpm_root,
                &store,
                &crate::commands::cache::PruneFlags::default(),
                None,
            ) {
                Ok(plan) => {
                    orphan_links += plan.link_entries_orphaned.len();
                    orphan_objects += plan.object_entries_orphaned.len();
                    orphan_bytes = orphan_bytes.saturating_add(plan.bytes_freed_or_eligible);
                }
                Err(_) => plans_valid = false,
            }
        }
        if plans_valid {
            if orphan_links == 0 && orphan_objects == 0 {
                checks.push(Check::pass(&doctor_catalog::V2_STORE_ORPHANS, "no orphans"));
            } else {
                checks.push(Check::warn(
                    &doctor_catalog::V2_STORE_ORPHANS,
                    &format!(
                        "{orphan_links} link orphan{} + {orphan_objects} object orphan{} \
                         ({}); run: lpm cache prune --apply",
                        if orphan_links == 1 { "" } else { "s" },
                        if orphan_objects == 1 { "" } else { "s" },
                        lpm_common::format_bytes(orphan_bytes),
                    ),
                ));
            }
        }
    }

    // 6. Lockfile? (Fast — load-bearing for install)
    checks.extend(check_lockfile_state(project_dir));

    // 6b. .gitattributes hygiene (Extended) — git-side correctness for
    // the binary lockfile, not a runtime-install gate.
    if all {
        checks.extend(check_gitattributes_state(project_dir));
    }

    // 6c. Dependencies in sync? (lockfile vs package.json)
    if pkg_json_path.exists()
        && let Some(sync_check) = check_deps_in_sync(project_dir)
    {
        checks.push(sync_check);
    }

    // 6d. file:/link: source health.
    // Reports broken paths, missing package.json, exotic file types
    // — anything that would cause a runtime install error users
    // could pre-detect.
    if pkg_json_path.exists() {
        checks.extend(check_local_source_paths(project_dir));
    }

    // === lpm.json Validation ===

    // 7. Validate lpm.json (if exists)
    if let Some(lpm_json_check) = validate_lpm_json(project_dir) {
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
    if all && pkg_json_path.exists() {
        checks.extend(check_manifest_compat(project_dir));
    }

    // === Runtime ===

    // 8. Node.js version
    let detected = lpm_runtime::detect::detect_node_version(project_dir)?;
    let script_path = lpm_runner::bin_path::build_path_with_bins(project_dir)?;
    let effective_node = lpm_runtime::effective::resolve_node_on_path_with_fingerprint(
        project_dir,
        std::ffi::OsStr::new(&script_path),
    );
    let effective_version = effective_node
        .version()
        .map(|version| format!("v{version}"));

    if let Some(requirement) =
        crate::engine_check::resolve_root_node_engine_requirement(project_dir)?
        && let Some(actual) = effective_node.version()
    {
        let source = "script PATH";
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
        let managed_versions = lpm_runtime::node::list_installed().unwrap_or_default();

        let spec = &det.spec;
        let clean = spec
            .trim_start_matches(">=")
            .trim_start_matches('^')
            .trim_start_matches('~')
            .trim_start_matches('>');

        let matched_managed = lpm_runtime::node::find_matching_installed(clean, &managed_versions);

        if let Some(ver) = matched_managed {
            checks.push(Check::pass(
                &doctor_catalog::NODE_MANAGED_MATCH,
                &format!("v{ver} (managed, from {})", det.source_label()),
            ));
        } else if let Some(sys) = &effective_version {
            checks.push(Check::warn(&doctor_catalog::NODE_PINNED_UNMET, &format!(
					"{sys} (script PATH) — pinned {spec} from {} not installed. Run: lpm use node@{clean}",
					det.source_label()
				),));
        } else {
            checks.push(Check::fail(
                &doctor_catalog::NODE_MISSING_PINNED,
                &format!(
                    "not found — pinned {spec} from {}. Run: lpm use node@{clean}",
                    det.source_label()
                ),
            ));
        }
    } else {
        if let Some(v) = effective_version {
            checks.push(Check::pass(
                &doctor_catalog::NODE_SYSTEM_UNPINNED,
                &format!("{v} (script PATH, no version pinned)"),
            ));
        } else {
            checks.push(Check::fail(
                &doctor_catalog::NODE_MISSING_UNPINNED,
                "not found — run: lpm use node@22",
            ));
        }
    }

    if let Some(det) = lpm_runtime::detect::detect_bun_version(project_dir)? {
        let system_bun = get_system_bun_version(project_dir)?;
        let managed_versions = lpm_runtime::bun::list_installed().unwrap_or_default();
        let spec = &det.spec;
        let clean = lpm_runtime::bun::normalize_spec(spec);
        let matched_managed = lpm_runtime::bun::find_matching_installed(spec, &managed_versions);

        if let Some(ver) = matched_managed {
            checks.push(Check::pass(
                &doctor_catalog::BUN_MANAGED_MATCH,
                &format!("{ver} (managed, from {})", det.source),
            ));
        } else if let Some(sys) = &system_bun {
            checks.push(Check::warn(
                &doctor_catalog::BUN_PINNED_UNMET,
                &format!(
                    "{sys} (system) — pinned {spec} from {} not installed. Run: lpm use bun@{clean}",
                    det.source
                ),
            ));
        } else {
            checks.push(Check::fail(
                &doctor_catalog::BUN_MISSING_PINNED,
                &format!(
                    "not found — pinned {spec} from {}. Run: lpm use bun@{clean}",
                    det.source
                ),
            ));
        }
    }

    // === Tunnel  ===
    //
    // Touches network in the authenticated path (`tunnel_domain_lookup`
    // + HTTP reachability probe). Skipped on fast path.
    if all {
        let tunnel_checks = check_tunnel_domain(project_dir, client, token_exists).await;
        checks.extend(tunnel_checks);
    }

    // === Code Quality + TypeScript + Plugins  ===
    //
    // Subprocess spawns (oxlint, biome) + network calls (plugin
    // version fetch). All Extended-tier; default fast preset stays
    // pure local file I/O. TypeScript readiness is a cheap file probe
    // but lives next to the tooling cluster the user expects to see
    // together — promoted under `--all` for output cohesion.
    if all {
        // Lint check (if oxlint installed)
        if let Some(lint_result) = run_lint_check(project_dir) {
            checks.push(lint_result);
        }

        // Format check (if biome installed)
        if let Some(fmt_result) = run_fmt_check(project_dir) {
            checks.push(fmt_result);
        }

        // TypeScript readiness — workspace-aware reachability check.
        // Cheap local-bin lookup + dep-declaration check, no blocking
        // `tsc --noEmit` invocation. The actual type-check belongs to
        // `lpm check`; doctor only verifies the project is set up so
        // that `lpm check` will work when the user runs it.
        checks.extend(check_typescript_setup(project_dir));

        // Plugin status — fetches latest plugin versions in parallel.
        let plugin_checks = check_plugins().await;
        checks.extend(plugin_checks);
    }

    // === Workspace ===

    // 13. Workspace health
    if let Some(ws_check) = check_workspace(project_dir) {
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
        for check in check_global_installs() {
            checks.push(check);
        }
    }

    // Sigstore provenance posture (Fast) — surfaces the resolved
    // `EnforceMode` (env > [sigstore].verify > default) so an
    // operator who flipped the knob once and forgot doesn't fly
    // blind. Fast-tier: one config-file read, no network.
    checks.push(check_sigstore_verify_posture());

    // === — Script policy + sandbox (Extended) ===
    //
    //   18. Sandbox availability — probe the per-platform backend.
    //   19. Script-policy scope boundary — project installs only in 46.0;
    //                                      globals ship with     //
    // Behind `--all`: sandbox + policy diagnostics report on host
    // capabilities (kernel version, helper availability) rather than
    // current-project breakage.
    if all {
        for check in check_script_policy_surface() {
            checks.push(check);
        }
    }

    if let Some(progress) = sweep_progress.take() {
        progress.settle();
    }

    // === Auto-fix (runs before output so JSON includes fixes_applied) ===
    if fix {
        if !json_output {
            install_ui::phase("Running auto-fix");
        }

        let mut install_ran = false;

        for check in &checks {
            // Auto-fix dispatch keys on the stable `code` field so
            // wording tweaks to `name` / `detail` never silently break
            // a fix branch. Each branch handles the codes that share a
            // remediation; passing-state codes never reach here because
            // the outer loop only enters `--fix` when there's something
            // to fix.
            match check.code() {
                "node_modules_missing"
                | "node_modules_no_store"
                | "node_modules_legacy_layout"
                | "node_modules_mixed_layout"
                    if !install_ran =>
                {
                    if !json_output {
                        install_ui::phase("fixing: lpm install");
                    }
                    match run_doctor_install(client, project_dir).await {
                        Ok(()) => {
                            fixes_applied.push("lpm install".into());
                            install_ran = true;
                        }
                        Err(e) => render_autofix_failed("lpm install", &e),
                    }
                }
                "node_pinned_unmet" | "node_missing_pinned" | "node_missing_unpinned" => {
                    if let Some(spec) = extract_node_spec_from_detail(&check.detail) {
                        if !json_output {
                            install_ui::phase_untrusted(&format!(
                                "fixing: lpm use node@{}",
                                lpm_common::sanitize_terminal_inline(&spec)
                            ));
                        }
                        let http_client = lpm_http::client_builder()
                            .timeout(std::time::Duration::from_secs(60))
                            .build()
                            .map_err(|e| LpmError::Network(format!("{e}")))?;
                        let platform = lpm_runtime::platform::Platform::current()?;
                        let releases = lpm_runtime::node::fetch_index(&http_client).await;
                        if let Ok(releases) = releases
                            && let Some(release) =
                                lpm_runtime::node::resolve_version(&releases, &spec)
                        {
                            match lpm_runtime::download::install_node(
                                &http_client,
                                &release,
                                &platform,
                            )
                            .await
                            {
                                Ok(ver) => fixes_applied.push(format!("installed node {ver}")),
                                Err(e) => render_autofix_failed("node install", &e),
                            }
                        }
                    }
                }
                "fmt_unformatted" | "fmt_other_issue" => {
                    if !json_output {
                        install_ui::phase("fixing: lpm fmt");
                    }
                    let result = crate::commands::tools::fmt(project_dir, &[], false, false).await;
                    match result {
                        Ok(()) => fixes_applied.push("lpm fmt".into()),
                        Err(e) => render_autofix_failed("lpm fmt", &e),
                    }
                }
                "lockfile_missing" if !install_ran => {
                    if !json_output {
                        install_ui::phase("fixing: lpm install (generates lockfile)");
                    }
                    match run_doctor_install(client, project_dir).await {
                        Ok(()) => {
                            fixes_applied.push("lpm install (lockfile)".into());
                            install_ran = true;
                        }
                        Err(e) => render_autofix_failed("lpm install", &e),
                    }
                }
                "deps_sync_drift" if !install_ran => {
                    if !json_output {
                        install_ui::phase("fixing: lpm install (sync lockfile)");
                    }
                    match run_doctor_install(client, project_dir).await {
                        Ok(()) => {
                            fixes_applied.push("lpm install (deps sync)".into());
                            install_ran = true;
                        }
                        Err(e) => render_autofix_failed("lpm install", &e),
                    }
                }
                "lockfile_binary_stale" | "lockfile_binary_corrupt" | "lockfile_binary_missing" => {
                    if !json_output {
                        install_ui::phase("fixing: reconciling lpm.lockb with lpm.lock");
                    }
                    match fix_binary_lockfile(project_dir) {
                        Ok(()) => fixes_applied.push("reconciled lpm.lockb".into()),
                        Err(e) => render_autofix_failed("reconcile lpm.lockb", &e),
                    }
                }
                "gitattributes_missing" | "gitattributes_lockb_unmarked" => {
                    if !json_output {
                        install_ui::phase(
                            "fixing: ensuring .gitattributes marks lpm.lockb as binary",
                        );
                    }
                    match fix_gitattributes(project_dir) {
                        Ok(()) => fixes_applied.push("updated .gitattributes".into()),
                        Err(e) => render_autofix_failed("update .gitattributes", &e),
                    }
                }
                "tunnel_not_claimed" => {
                    // Extract domain from detail: "acme-api.lpm.llc — not claimed ..."
                    if let Some(domain) = check.detail.split(" —").next() {
                        let domain = domain.trim();
                        if !json_output {
                            install_ui::phase_untrusted(&format!(
                                "fixing: lpm tunnel claim {}",
                                lpm_common::sanitize_terminal_inline(domain)
                            ));
                        }
                        match client.tunnel_claim(domain, None).await {
                            Ok(_) => {
                                fixes_applied.push(format!("claimed tunnel domain {domain}"));
                            }
                            Err(e) => render_autofix_failed("tunnel claim", &e),
                        }
                    }
                }
                _ => {}
            }
        }

        if !json_output {
            if fixes_applied.is_empty() {
                install_ui::phase("no auto-fixable issues found");
            } else {
                install_ui::done_untrusted(&format!(
                    "applied {} fix(es): {}",
                    fixes_applied.len(),
                    fixes_applied.join(", ")
                ));
                install_ui::detail_line(crate::install_ui::terminal_line!(
                    "  {} Run {} to verify fixes.",
                    install_ui::dim("hint"),
                    install_ui::yellow("lpm doctor")
                ));
            }
        }
    }

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
        let results: Vec<_> = checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "code": c.code(),
                    "check": c.name(),
                    "passed": c.passed,
                    "severity": c.severity.as_str(),
                    "detail": c.detail,
                })
            })
            .collect();
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;
        let warning_count = checks
            .iter()
            .filter(|c| matches!(c.severity, Severity::Warn))
            .count();
        let passed_count = checks.iter().filter(|c| c.passed).count();
        let failed_count = checks.iter().filter(|c| !c.passed).count();
        let output = serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "mode": mode_str,
            "no_failures": no_failures,
            "clean": clean,
            "has_warnings": has_warnings,
            "checks": results,
            "passed": passed_count,
            "failed": failed_count,
            "warnings": warning_count,
            "fixes_applied": fixes_applied,
        }))
        .map_err(|e| LpmError::Script(format!("failed to serialize doctor output: {e}")))?;
        println!("{output}");
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
    let has_failures = checks.iter().any(|c| !c.passed);
    if has_failures {
        return Err(LpmError::ExitCode(1));
    }

    Ok(())
}

fn render_autofix_failed(action: &str, error: &impl std::fmt::Display) {
    let error = error.to_string();
    install_ui::failed_untrusted(&format!(
        "{} failed: {}",
        lpm_common::sanitize_terminal_inline(action),
        lpm_common::sanitize_terminal_inline(&error)
    ));
}
