use crate::doctor_catalog::{self, CheckEntry, Severity};
use crate::{auth, output};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use lpm_store::PackageStore;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Check result emitted by `lpm doctor`.
///
/// Carries a typed reference to a [`CheckEntry`] from
/// [`crate::doctor_catalog`] — every emitted code is, by
/// construction, a registered catalog entry. The constructor
/// `debug_assert!`s that the chosen severity is one the catalog
/// declares the code can take, so wording-and-severity drift cannot
/// silently slip in.
///
/// `name` and `code` flow from the entry; only `detail` and
/// `severity` are runtime-owned.
struct Check {
    /// Reference to the canonical catalog entry. `code` and `name`
    /// flow from here.
    entry: &'static CheckEntry,
    passed: bool,
    detail: String,
    severity: Severity,
}

impl Check {
    fn pass(entry: &'static CheckEntry, detail: &str) -> Self {
        debug_assert!(
            entry.permits(Severity::Pass),
            "catalog entry `{}` does not permit Pass — declared severities: {:?}",
            entry.code,
            entry.possible_severities,
        );
        Self {
            entry,
            passed: true,
            detail: detail.into(),
            severity: Severity::Pass,
        }
    }

    fn fail(entry: &'static CheckEntry, detail: &str) -> Self {
        debug_assert!(
            entry.permits(Severity::Fail),
            "catalog entry `{}` does not permit Fail — declared severities: {:?}",
            entry.code,
            entry.possible_severities,
        );
        Self {
            entry,
            passed: false,
            detail: detail.into(),
            severity: Severity::Fail,
        }
    }

    fn warn(entry: &'static CheckEntry, detail: &str) -> Self {
        debug_assert!(
            entry.permits(Severity::Warn),
            "catalog entry `{}` does not permit Warn — declared severities: {:?}",
            entry.code,
            entry.possible_severities,
        );
        Self {
            entry,
            passed: true,
            detail: detail.into(),
            severity: Severity::Warn,
        }
    }

    /// Stable machine-readable identifier — match on this in
    /// automation. Flat accessor over `entry.code` so the JSON
    /// serializer and human renderer don't need to reach through
    /// the catalog reference.
    fn code(&self) -> &'static str {
        self.entry.code
    }

    /// Human-readable label. Flat accessor over `entry.name`.
    fn name(&self) -> &'static str {
        self.entry.name
    }
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

    output::print_header();
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
    if !json_output {
        output::print_header();
    }

    let mut checks: Vec<Check> = Vec::new();
    let mut fixes_applied: Vec<String> = Vec::new();

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
    if let Ok(pkg_content) = std::fs::read_to_string(&pkg_json_path)
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
    // — pass the v2 links root so the health probe can
    // recognize a virtual-store install (no `.lpm/wrappers/` and no
    // `.lpm/hoisted/metadata.json`, but project-side `node_modules/`
    // symlinks pointing into `~/.lpm/store/v2/links/`). On a system
    // where `LpmRoot::from_env` fails (extremely rare; no $HOME and
    // no $LPM_HOME), the check degrades to legacy v1-only detection.
    let v2_links_root = lpm_common::LpmRoot::from_env()
        .ok()
        .map(|root| lpm_store::v2::StoreV2Paths::from_lpm_root(&root).links_root());
    if layout.needs_layout_migration() {
        checks.push(Check::warn(&doctor_catalog::NODE_MODULES_LEGACY_LAYOUT, "legacy wrapper layout detected — run: lpm install (one-time migration to .lpm/wrappers/)",));
    } else {
        match layout.install_appears_healthy_with_v2(v2_links_root.as_deref()) {
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
                    "symlinks into ~/.lpm/store/v2/links/",
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

    // === V2 store orphan stats (Extended) ===
    //
    // (preplan). Cheap but cross-project
    // hygiene rather than core breakage — only surface under `--all`.
    // Walks `~/.lpm/store/v2/links/<*>/.lpm-link-meta.json` sidecars
    // + the registered-projects set, surfaces a count of orphans not
    // reachable from any project.
    if all && let Ok(lpm_root) = lpm_common::LpmRoot::from_env() {
        let v2_store = lpm_store::v2::Store::from_lpm_root(&lpm_root);
        let plan = crate::commands::cache_prune::compute_prune_plan(
            &lpm_root,
            &v2_store,
            &crate::commands::cache::PruneFlags::default(),
            None,
        );
        if let Ok(plan) = plan {
            let orphan_links = plan.link_entries_orphaned.len();
            let orphan_objects = plan.object_entries_orphaned.len();
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
                        lpm_common::format_bytes(plan.bytes_freed_or_eligible),
                    ),
                ));
            }
        }
    }

    // 6. Lockfile? (Fast — load-bearing for install)
    let lockfile = project_dir.join("lpm.lock");
    checks.extend(check_lockfile_state(project_dir));

    // 6b. .gitattributes hygiene (Extended) — git-side correctness for
    // the binary lockfile, not a runtime-install gate.
    if all {
        checks.extend(check_gitattributes_state(project_dir));
    }

    // 6c. Dependencies in sync? (lockfile vs package.json)
    if lockfile.exists()
        && pkg_json_path.exists()
        && let Some(sync_check) = check_deps_in_sync(project_dir)
    {
        checks.push(sync_check);
    }

    // 6d. day-7 (F17): file:/link: source health.
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
    // #61. Surfaces every issue from
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
    let detected = lpm_runtime::detect::detect_node_version(project_dir);
    if let Some(ref det) = detected {
        let system_node = get_system_node_version(project_dir);
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
                &format!("v{ver} (managed, from {})", det.source),
            ));
        } else if let Some(sys) = &system_node {
            checks.push(Check::warn(&doctor_catalog::NODE_PINNED_UNMET, &format!(
					"{sys} (system) — pinned {spec} from {} not installed. Run: lpm use node@{clean}",
					det.source
				),));
        } else {
            checks.push(Check::fail(
                &doctor_catalog::NODE_MISSING_PINNED,
                &format!(
                    "not found — pinned {spec} from {}. Run: lpm use node@{clean}",
                    det.source
                ),
            ));
        }
    } else {
        let sys = get_system_node_version(project_dir);
        if let Some(v) = sys {
            checks.push(Check::pass(
                &doctor_catalog::NODE_SYSTEM_UNPINNED,
                &format!("{v} (system, no version pinned)"),
            ));
        } else {
            checks.push(Check::fail(
                &doctor_catalog::NODE_MISSING_UNPINNED,
                "not found — run: lpm use node@22",
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

    // === Auto-fix (runs before output so JSON includes fixes_applied) ===
    if fix {
        if !json_output {
            println!();
            output::info("Running auto-fix...");
            println!();
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
                | "node_modules_mixed_layout" => {
                    if !install_ran {
                        if !json_output {
                            output::info("fixing: lpm install");
                        }
                        match run_doctor_install(client, project_dir).await {
                            Ok(()) => {
                                fixes_applied.push("lpm install".into());
                                install_ran = true;
                            }
                            Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm install failed: {e}"),
                        }
                    }
                }
                "node_pinned_unmet" | "node_missing_pinned" | "node_missing_unpinned" => {
                    if let Some(spec) = extract_node_spec_from_detail(&check.detail) {
                        if !json_output {
                            output::info(&format!("fixing: lpm use node@{spec}"));
                        }
                        let http_client = reqwest::Client::builder()
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
                                Err(e) => eprintln!("  \x1b[31m✖\x1b[0m node install failed: {e}"),
                            }
                        }
                    }
                }
                "fmt_unformatted" | "fmt_other_issue" => {
                    if !json_output {
                        output::info("fixing: lpm fmt");
                    }
                    let result = crate::commands::tools::fmt(project_dir, &[], false, false).await;
                    match result {
                        Ok(()) => fixes_applied.push("lpm fmt".into()),
                        Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm fmt failed: {e}"),
                    }
                }
                "lockfile_missing" => {
                    if !install_ran {
                        if !json_output {
                            output::info("fixing: lpm install (generates lockfile)");
                        }
                        match run_doctor_install(client, project_dir).await {
                            Ok(()) => {
                                fixes_applied.push("lpm install (lockfile)".into());
                                install_ran = true;
                            }
                            Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm install failed: {e}"),
                        }
                    }
                }
                "deps_sync_drift" => {
                    if !install_ran {
                        if !json_output {
                            output::info("fixing: lpm install (sync lockfile)");
                        }
                        match run_doctor_install(client, project_dir).await {
                            Ok(()) => {
                                fixes_applied.push("lpm install (deps sync)".into());
                                install_ran = true;
                            }
                            Err(e) => eprintln!("  \x1b[31m✖\x1b[0m lpm install failed: {e}"),
                        }
                    }
                }
                "lockfile_binary_stale" | "lockfile_binary_corrupt" | "lockfile_binary_missing" => {
                    if !json_output {
                        output::info("fixing: regenerating lpm.lockb from lpm.lock");
                    }
                    match fix_binary_lockfile(project_dir) {
                        Ok(()) => fixes_applied.push("regenerated lpm.lockb".into()),
                        Err(e) => eprintln!("  \x1b[31m✖\x1b[0m {e}"),
                    }
                }
                "gitattributes_missing" | "gitattributes_lockb_unmarked" => {
                    if !json_output {
                        output::info("fixing: ensuring .gitattributes marks lpm.lockb as binary");
                    }
                    match fix_gitattributes(project_dir) {
                        Ok(()) => fixes_applied.push("updated .gitattributes".into()),
                        Err(e) => eprintln!("  \x1b[31m✖\x1b[0m {e}"),
                    }
                }
                "tunnel_not_claimed" => {
                    // Extract domain from detail: "acme-api.lpm.llc — not claimed ..."
                    if let Some(domain) = check.detail.split(" —").next() {
                        let domain = domain.trim();
                        if !json_output {
                            output::info(&format!("fixing: lpm tunnel claim {domain}"));
                        }
                        match client.tunnel_claim(domain, None).await {
                            Ok(_) => {
                                fixes_applied.push(format!("claimed tunnel domain {domain}"));
                            }
                            Err(e) => {
                                eprintln!("  \x1b[31m✖\x1b[0m tunnel claim failed: {e}");
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if !json_output {
            if fixes_applied.is_empty() {
                output::info("no auto-fixable issues found");
            } else {
                println!();
                output::success(&format!(
                    "applied {} fix(es): {}",
                    fixes_applied.len(),
                    fixes_applied.join(", ")
                ));
                println!("\n  Run {} to verify fixes.", "lpm doctor".bold());
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
        println!();
        for check in &checks {
            if !all
                && matches!(check.severity, Severity::Pass)
                && check.code() != doctor_catalog::LINKER_MODE_RESOLVED.code
            {
                continue;
            }
            let icon = match check.severity {
                Severity::Pass => "✔".green().to_string(),
                Severity::Fail => "✖".red().to_string(),
                Severity::Warn => "⚠".yellow().to_string(),
            };
            println!("  {icon} {} {}", check.name().bold(), check.detail.dimmed());
        }
        println!();

        if failed == 0 && warned == 0 {
            output::success(&format!("All {total} checks passed"));
            if !all {
                println!(
                    "\n  Run {} for registry, auth, tunnel, tooling, plugin, global,\n  \
                     sandbox, and full manifest-compat diagnostics.",
                    "lpm doctor --all".bold()
                );
            }
        } else if failed == 0 {
            output::success(&format!(
                "{} checks passed, {} warning(s)",
                total - warned,
                warned
            ));
        } else {
            output::warn(&format!("{failed} check(s) failed, {warned} warning(s)"));
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

/// Extract node version spec from doctor detail message.
fn extract_node_spec_from_detail(detail: &str) -> Option<String> {
    // "... pinned >=22 from ... Run: lpm use node@22"
    if let Some(pos) = detail.find("node@") {
        let after = &detail[pos + 5..];
        let end = after
            .find(|c: char| c.is_whitespace() || c == '"')
            .unwrap_or(after.len());
        return Some(after[..end].to_string());
    }
    // Fallback: "not found — run: lpm use node@22"
    None
}

// --- Check helpers ---

/// Get system Node.js version by running `node --version`.
fn get_system_node_version(project_dir: &Path) -> Option<String> {
    let path = lpm_runner::bin_path::build_path_with_bins(project_dir);
    let output = Command::new("node")
        .arg("--version")
        .env("PATH", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Run a tool command with a 30-second timeout.
/// Returns (stdout, stderr, exit_code) or None on timeout/error.
fn run_tool_with_timeout(
    cmd: &Path,
    args: &[&str],
    cwd: &Path,
    extra_path: Option<&str>,
) -> Option<(String, String, i32)> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(path) = extra_path {
        command.env("PATH", path);
    }

    let child = command.spawn().ok()?;

    // Wait with timeout
    let output = wait_with_timeout(child, Duration::from_secs(30))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(1);

    Some((stdout, stderr, code))
}

/// Wait for a child process with timeout. Returns None if timed out.
///
/// Uses exponential backoff (10ms → 20ms → … → 200ms cap) to avoid busy-waiting
/// while still returning promptly for fast-completing tools.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Option<std::process::Output> {
    let start = std::time::Instant::now();
    let mut sleep_ms: u64 = 10;
    const MAX_SLEEP_MS: u64 = 200;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = child
                    .stdout
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut s, &mut buf).ok();
                        buf
                    })
                    .unwrap_or_default();
                let stderr = child
                    .stderr
                    .map(|mut s| {
                        let mut buf = Vec::new();
                        std::io::Read::read_to_end(&mut s, &mut buf).ok();
                        buf
                    })
                    .unwrap_or_default();
                return Some(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(sleep_ms));
                sleep_ms = (sleep_ms * 2).min(MAX_SLEEP_MS);
            }
            Err(_) => return None,
        }
    }
}

/// Run oxlint silently and count errors/warnings (30s timeout).
fn run_lint_check(project_dir: &Path) -> Option<Check> {
    let (_version, bin) = lpm_plugin::find_installed_for_current_platform("oxlint", "oxlint")?;

    let (stdout, _stderr, code) = run_tool_with_timeout(&bin, &["."], project_dir, None)?;

    if code == 0 {
        return Some(Check::pass(&doctor_catalog::LINT_CLEAN, "no issues"));
    }

    // Try to parse oxlint summary line, fall back to exit code
    if let Some(summary) = stdout.lines().rev().find(|l| l.contains("Found")) {
        let has_errors = summary.contains("error");
        if has_errors {
            Some(Check::fail(
                &doctor_catalog::LINT_ERRORS,
                &format!("{} — run: lpm lint --fix", summary.trim()),
            ))
        } else {
            Some(Check::warn(
                &doctor_catalog::LINT_WARNINGS,
                &format!("{} — run: lpm lint --fix", summary.trim()),
            ))
        }
    } else {
        // Fallback: couldn't parse output, use exit code
        Some(Check::warn(
            &doctor_catalog::LINT_UNPARSEABLE,
            &format!("exited with code {code} — run: lpm lint for details"),
        ))
    }
}

/// Run biome format --check silently (30s timeout).
fn run_fmt_check(project_dir: &Path) -> Option<Check> {
    let (_version, bin) = lpm_plugin::find_installed_for_current_platform("biome", "biome")?;

    let (_stdout, stderr, code) =
        run_tool_with_timeout(&bin, &["format", "--check", "."], project_dir, None)?;

    if code == 0 {
        return Some(Check::pass(
            &doctor_catalog::FMT_CLEAN,
            "all files formatted",
        ));
    }

    // Try to count unformatted files, fall back to exit code
    let count = stderr
        .lines()
        .filter(|l| l.contains("Formatter would have printed"))
        .count();
    if count > 0 {
        Some(Check::warn(
            &doctor_catalog::FMT_UNFORMATTED,
            &format!("{count} file(s) need formatting — run: lpm fmt"),
        ))
    } else {
        Some(Check::warn(
            &doctor_catalog::FMT_OTHER_ISSUE,
            &format!("formatting issues found (exit {code}) — run: lpm fmt"),
        ))
    }
}

/// TypeScript readiness checks — one per tsconfig-owning directory.
/// Workspace-aware: in a monorepo this emits a check for the root (if
/// it has a `tsconfig.json`) plus every member with a local
/// `tsconfig.json`.
///
/// Codes:
///
/// - `typescript_healthy` (pass) — `tsc` resolves through the local
///   `node_modules/.bin` chain. Editor (`tsserver` from
///   `node_modules/typescript`) and CI agree on the version.
/// - `typescript_missing_for_tsconfig` (warn) — `tsc` runs only via
///   the system `PATH`. The project lacks a local install, so editor
///   and CI may use a different version. Fix: `lpm install -D typescript`.
/// - `typescript_unavailable` (fail) — `tsc` cannot run at all. Fix
///   depends on whether `typescript` is already declared (run `lpm
///   install`) or needs to be added (run `lpm install -D typescript`).
fn check_typescript_setup(project_dir: &Path) -> Vec<Check> {
    let mut checks = Vec::new();

    let dirs = collect_tsconfig_dirs(project_dir);
    if dirs.is_empty() {
        return checks;
    }

    for dir in dirs {
        let status = crate::tsc_status::TscStatus::probe(&dir);
        let label = label_for_tsconfig(project_dir, &dir);

        if let Some(ref bin) = status.local_bin {
            checks.push(Check::pass(
                &doctor_catalog::TYPESCRIPT_HEALTHY,
                &format!("{label}local tsc resolves at {}", bin.display()),
            ));
        } else if status.system_bin.is_some() {
            checks.push(Check::warn(&doctor_catalog::TYPESCRIPT_MISSING_FOR_TSCONFIG, &format!(
                    "{label}using system tsc — editor + CI may diverge. Run: lpm install -D typescript"
                ),));
        } else if status.in_deps {
            checks.push(Check::fail(
                &doctor_catalog::TYPESCRIPT_UNAVAILABLE,
                &format!("{label}declared but not installed — run: lpm install"),
            ));
        } else {
            checks.push(Check::fail(
                &doctor_catalog::TYPESCRIPT_UNAVAILABLE,
                &format!("{label}not installed — run: lpm install -D typescript"),
            ));
        }
    }

    checks
}

/// Collect every directory in the workspace that owns a `tsconfig.json`.
/// Always includes `project_dir` if it has one. In a workspace, also
/// includes every member directory with a `tsconfig.json` — covers the
/// monorepo case where `run_typecheck` previously missed every member.
fn collect_tsconfig_dirs(project_dir: &Path) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();

    if project_dir.join("tsconfig.json").is_file() {
        dirs.push(project_dir.to_path_buf());
    }

    if let Ok(Some(workspace)) = lpm_workspace::discover_workspace(project_dir) {
        for member in &workspace.members {
            if member.path == project_dir {
                continue;
            }
            if member.path.join("tsconfig.json").is_file() {
                dirs.push(member.path.clone());
            }
        }
    }

    dirs
}

/// Format a relative-path prefix for a tsconfig directory. Empty when
/// `dir` is the project root (the common single-package case).
fn label_for_tsconfig(project_dir: &Path, dir: &Path) -> String {
    if dir == project_dir {
        return String::new();
    }
    if let Ok(rel) = dir.strip_prefix(project_dir) {
        return format!("{}: ", rel.display());
    }
    format!("{}: ", dir.display())
}

/// Check installed plugins for available updates.
///
/// Fetches latest versions in parallel for all installed plugins.
async fn check_plugins() -> Vec<Check> {
    let plugins: Vec<_> = lpm_plugin::registry::list_plugins()
        .iter()
        .filter_map(|def| {
            let installed =
                lpm_plugin::store::list_installed_versions(def.name).unwrap_or_default();
            if installed.is_empty() {
                return None;
            }
            Some((def, installed))
        })
        .collect();

    let futures: Vec<_> = plugins
        .iter()
        .map(|(def, _installed)| lpm_plugin::versions::get_latest_version(def))
        .collect();

    let latest_versions = futures::future::join_all(futures).await;

    let mut checks = Vec::new();
    for ((def, installed), latest) in plugins.iter().zip(latest_versions) {
        let Some(current) = installed.last() else {
            continue;
        };

        if *current == latest {
            checks.push(Check::pass(
                &doctor_catalog::PLUGIN_UP_TO_DATE,
                &format!("{}: v{current} (up to date)", def.name),
            ));
        } else {
            checks.push(Check::warn(
                &doctor_catalog::PLUGIN_UPDATE_AVAILABLE,
                &format!(
                    "{}: v{current} → v{latest} available — run: lpm plugin update {}",
                    def.name, def.name,
                ),
            ));
        }
    }

    checks
}

/// Check workspace graph for cycles.
fn check_workspace(project_dir: &Path) -> Option<Check> {
    let workspace = lpm_workspace::discover_workspace(project_dir).ok()??;
    let graph = lpm_task::graph::WorkspaceGraph::from_workspace(&workspace);

    match graph.topological_sort() {
        Ok(sorted) => Some(Check::pass(
            &doctor_catalog::WORKSPACE_ACYCLIC,
            &format!("{} packages, no dependency cycles", sorted.len()),
        )),
        Err(e) => Some(Check::fail(
            &doctor_catalog::WORKSPACE_CYCLE,
            &format!("{e} — resolve circular dependencies"),
        )),
    }
}

/// Check tunnel domain configuration from lpm.json.
///
/// Performs format validation (RFC 1035/1123 compliance, subdomain constraints,
/// known base domain whitelist), ownership check (via registry API when authenticated),
/// and HTTP reachability check for claimed domains.
async fn check_tunnel_domain(
    project_dir: &Path,
    client: &RegistryClient,
    is_authenticated: bool,
) -> Vec<Check> {
    let config = match lpm_runner::lpm_json::read_lpm_json(project_dir) {
        Ok(Some(c)) => c,
        _ => return vec![],
    };
    let tunnel = match config.tunnel {
        Some(t) => t,
        None => return vec![],
    };
    let domain = match tunnel.domain {
        Some(d) => d,
        None => return vec![],
    };

    let mut checks = Vec::new();

    // RFC-compliant domain length checks (RFC 1035 / RFC 1123)
    if domain.len() > 253 {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_DOMAIN_TOO_LONG,
            &format!(
                "domain \"{}\" exceeds 253 character limit ({} chars)",
                domain,
                domain.len()
            ),
        ));
        return checks;
    }

    // Check each label: max 63 chars, no empty labels (consecutive dots)
    for label in domain.split('.') {
        if label.is_empty() {
            checks.push(Check::warn(
                &doctor_catalog::TUNNEL_DOMAIN_EMPTY_LABEL,
                &format!("domain \"{domain}\" contains empty label (consecutive dots)"),
            ));
            return checks;
        }
        if label.len() > 63 {
            checks.push(Check::warn(
                &doctor_catalog::TUNNEL_DOMAIN_LABEL_TOO_LONG,
                &format!(
                    "domain label \"{}\" exceeds 63 character limit ({} chars)",
                    label,
                    label.len()
                ),
            ));
            return checks;
        }
    }

    // Validate domain format: must have at least one dot
    if !domain.contains('.') {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_DOMAIN_NO_DOT,
            &format!(
                "\"{}\" is not a full domain — use: {}.lpm.fyi or {}.lpm.llc",
                domain, domain, domain
            ),
        ));
        return checks;
    }

    // Split into subdomain + base domain (guaranteed to have a dot from check above)
    let parts: Vec<&str> = domain.splitn(2, '.').collect();
    let subdomain = parts[0];
    let base_domain = parts[1];

    // Check subdomain format
    if subdomain.len() < 3 || subdomain.len() > 32 {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_SUBDOMAIN_LENGTH,
            &format!("subdomain \"{subdomain}\" must be 3-32 characters"),
        ));
        return checks;
    }
    if !subdomain
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_SUBDOMAIN_CHARS,
            &format!("subdomain \"{subdomain}\" must be lowercase alphanumeric + hyphens"),
        ));
        return checks;
    }
    if subdomain.starts_with('-') || subdomain.ends_with('-') {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_SUBDOMAIN_HYPHEN,
            &format!("subdomain \"{subdomain}\" must not start or end with a hyphen"),
        ));
        return checks;
    }

    // Check known base domains — only deployed domains
    let known_bases = ["lpm.fyi", "lpm.llc"];
    if !known_bases.contains(&base_domain) {
        checks.push(Check::warn(
            &doctor_catalog::TUNNEL_UNKNOWN_BASE,
            &format!(
                "unknown base domain \"{base_domain}\" (available: {})",
                known_bases.join(", ")
            ),
        ));
        return checks;
    }

    // === Ownership check (requires auth) ===
    if !is_authenticated {
        checks.push(Check::pass(
            &doctor_catalog::TUNNEL_UNAUTHENTICATED,
            &format!("{domain} (configured, login to verify ownership)"),
        ));
        return checks;
    }

    // Check if domain is claimed by this user via registry API
    match client.tunnel_domain_lookup(&domain).await {
        Ok(result) => {
            let found = result["found"].as_bool().unwrap_or(false);
            let owned = result["ownedByYou"].as_bool().unwrap_or(false);

            if !found {
                checks.push(Check::warn(
                    &doctor_catalog::TUNNEL_NOT_CLAIMED,
                    &format!("{domain} — not claimed. Run: lpm tunnel claim {domain}"),
                ));
                return checks;
            }

            if !owned {
                checks.push(Check::warn(
                    &doctor_catalog::TUNNEL_OWNED_BY_OTHER,
                    &format!("{domain} — claimed by another user or org"),
                ));
                return checks;
            }

            // Domain is claimed and owned — check reachability
            let reachability = check_tunnel_reachability(&domain).await;
            match reachability {
                TunnelReachability::Active => {
                    checks.push(Check::pass(
                        &doctor_catalog::TUNNEL_ACTIVE,
                        &format!("{domain} (claimed, active)"),
                    ));
                }
                TunnelReachability::Idle => {
                    checks.push(Check::pass(
                        &doctor_catalog::TUNNEL_IDLE,
                        &format!("{domain} (claimed, idle)"),
                    ));
                }
                TunnelReachability::Unreachable => {
                    checks.push(Check::warn(
                        &doctor_catalog::TUNNEL_UNREACHABLE,
                        &format!("{domain} (claimed) — unreachable, DNS may not be configured"),
                    ));
                }
            }
        }
        Err(_) => {
            // API call failed — fall back to format-only validation
            checks.push(Check::pass(
                &doctor_catalog::TUNNEL_UNVERIFIED,
                &format!("{domain} (configured, could not verify ownership)"),
            ));
        }
    }

    checks
}

enum TunnelReachability {
    Active,
    Idle,
    Unreachable,
}

/// Quick HTTP HEAD check to see if a tunnel domain is reachable.
async fn check_tunnel_reachability(domain: &str) -> TunnelReachability {
    let url = format!("https://{domain}");
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return TunnelReachability::Unreachable,
    };

    match client.head(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 404 {
                // Worker returns 404 when tunnel is not active
                TunnelReachability::Idle
            } else {
                TunnelReachability::Active
            }
        }
        Err(_) => TunnelReachability::Unreachable,
    }
}

/// Check lockfile (lpm.lock + lpm.lockb) state: exists, in sync, valid.
/// verify every `file:` and `link:`
/// dep in package.json points at a usable local source.
///
/// What's reported:
/// - **Pass** when every local-source dep resolves to a valid target
///   (regular file for file: tarballs, directory containing
///   package.json for file:/link: directory deps).
/// - **Fail** for paths that don't exist or are unreadable —
///   `lpm install` would error at the manifest boundary; doctor
///   surfaces it pre-install so users can fix the package.json.
/// - **Fail** for `file:` directory targets without `package.json`.
/// - **Fail** for `link:` targets that resolve to a regular file
///   (link: requires a directory).
/// - **Fail** for exotic file types (devices, sockets) — same as
///   the manifest-boundary error in `pre_resolve_non_registry_deps`.
///
/// Each problem produces a separate Check entry so `--fix` /
/// human output / JSON all surface the per-dep detail. No
/// network or extraction work is done — just stat() per dep.
///
/// Returns an empty Vec when there are NO file:/link: deps (the
/// common case for non-monorepo projects). The doctor output stays
/// uncluttered.
fn check_local_source_paths(project_dir: &Path) -> Vec<Check> {
    let pkg_json_path = project_dir.join("package.json");
    let Ok(content) = std::fs::read_to_string(&pkg_json_path) else {
        return Vec::new();
    };
    let Ok(pkg) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };

    let mut checks = Vec::new();
    for field in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(deps) = pkg.get(field).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, raw) in deps {
            let Some(spec) = raw.as_str() else {
                continue;
            };
            // Classify: file: (tarball or dir), link: (dir only),
            // anything else → not our concern.
            let (kind_label, expected_dir, path_str) = if let Some(p) = spec.strip_prefix("file:") {
                ("file:", false, p) // false = could be tarball OR directory
            } else if let Some(p) = spec.strip_prefix("link:") {
                ("link:", true, p) // link: must be a directory
            } else {
                continue;
            };
            let abs = project_dir.join(path_str);
            match std::fs::metadata(&abs) {
                Ok(meta) if meta.is_dir() => {
                    // Directory target — must have package.json.
                    if !abs.join("package.json").is_file() {
                        checks.push(Check::fail(
                            &doctor_catalog::LOCAL_SOURCE_DIR_NO_PKG,
                            &format!(
                                "`{name}`: {kind_label}{path_str} resolves to a directory \
                                 without package.json — install will error",
                            ),
                        ));
                    } else {
                        checks.push(Check::pass(
                            &doctor_catalog::LOCAL_SOURCE_DIR_OK,
                            &format!("`{name}`: {kind_label}{path_str} (directory)"),
                        ));
                    }
                }
                Ok(meta) if meta.is_file() => {
                    if expected_dir {
                        // link: requires a directory.
                        checks.push(Check::fail(
                            &doctor_catalog::LOCAL_SOURCE_LINK_TO_FILE,
                            &format!(
                                "`{name}`: {kind_label}{path_str} resolves to a regular file; \
                                 link: requires a directory. Use file:./<name>.tgz \
                                 for tarballs",
                            ),
                        ));
                    } else {
                        checks.push(Check::pass(
                            &doctor_catalog::LOCAL_SOURCE_TARBALL_OK,
                            &format!("`{name}`: {kind_label}{path_str} (tarball)"),
                        ));
                    }
                }
                Ok(_) => {
                    checks.push(Check::fail(
                        &doctor_catalog::LOCAL_SOURCE_INVALID_TYPE,
                        &format!(
                            "`{name}`: {kind_label}{path_str} resolves to neither a regular \
                             file nor a directory (device/socket/etc.) — install \
                             will error",
                        ),
                    ));
                }
                Err(e) => {
                    checks.push(Check::fail(
                        &doctor_catalog::LOCAL_SOURCE_UNREADABLE,
                        &format!(
                            "`{name}`: {kind_label}{path_str} is unreadable: {e}. Check the \
                             path in package.json",
                        ),
                    ));
                }
            }
        }
    }
    checks
}

fn check_lockfile_state(project_dir: &Path) -> Vec<Check> {
    let lockfile = project_dir.join("lpm.lock");
    let lockb_path = project_dir.join("lpm.lockb");
    let mut checks = Vec::new();

    if lockfile.exists() {
        checks.push(Check::pass(&doctor_catalog::LOCKFILE_PRESENT, "lpm.lock"));

        if lockb_path.exists() {
            // Binary exists — check if in sync
            let toml_mtime = lockfile.metadata().and_then(|m| m.modified()).ok();
            let bin_mtime = lockb_path.metadata().and_then(|m| m.modified()).ok();

            let is_stale = match (toml_mtime, bin_mtime) {
                (Some(t), Some(b)) => b < t,
                _ => false,
            };

            if is_stale {
                checks.push(Check::warn(
                    &doctor_catalog::LOCKFILE_BINARY_STALE,
                    "lpm.lockb is stale — run lpm install to regenerate",
                ));
            } else {
                // Validate header
                match lpm_lockfile::binary::BinaryLockfileReader::open(&lockb_path) {
                    Ok(Some(_)) => checks.push(Check::pass(
                        &doctor_catalog::LOCKFILE_BINARY_VALID,
                        "lpm.lockb (in sync, valid)",
                    )),
                    Ok(None) => {} // shouldn't happen since we checked exists
                    Err(_) => {
                        checks.push(Check::warn(
                            &doctor_catalog::LOCKFILE_BINARY_CORRUPT,
                            "lpm.lockb is corrupt — run lpm install to regenerate",
                        ));
                    }
                }
            }
        } else {
            checks.push(Check::warn(
                &doctor_catalog::LOCKFILE_BINARY_MISSING,
                "lpm.lockb missing — run lpm install to generate",
            ));
        }
    } else {
        checks.push(Check::warn(
            &doctor_catalog::LOCKFILE_MISSING,
            "not found — run: lpm install to generate",
        ));
    }

    checks
}

/// Check .gitattributes state: exists and has lpm.lockb binary marker.
fn check_gitattributes_state(project_dir: &Path) -> Vec<Check> {
    let lockfile = project_dir.join("lpm.lock");
    let lockb_path = project_dir.join("lpm.lockb");
    let ga_path = project_dir.join(".gitattributes");
    let mut checks = Vec::new();

    if lockb_path.exists() || lockfile.exists() {
        if ga_path.exists() {
            let ga_content = std::fs::read_to_string(&ga_path).unwrap_or_default();
            if ga_content.lines().any(|l| l.trim() == "lpm.lockb binary") {
                checks.push(Check::pass(
                    &doctor_catalog::GITATTRIBUTES_LOCKB_MARKED,
                    "lpm.lockb marked as binary",
                ));
            } else {
                checks.push(Check::warn(
                    &doctor_catalog::GITATTRIBUTES_LOCKB_UNMARKED,
                    "lpm.lockb not marked as binary — run lpm install to fix",
                ));
            }
        } else {
            checks.push(Check::warn(
                &doctor_catalog::GITATTRIBUTES_MISSING,
                "missing — run lpm install to create (marks lpm.lockb as binary)",
            ));
        }
    }

    checks
}

/// Run `lpm install` with doctor-appropriate defaults (no security summary, no JSON output).
async fn run_doctor_install(client: &RegistryClient, project_dir: &Path) -> Result<(), LpmError> {
    crate::commands::install::run_with_options(
        client,
        project_dir,
        false,                                                   // json_output
        false,                                                   // offline
        false,                                                   // force
        false,                                                   // allow_new
        false,                                                   // strict_integrity
        None,                                                    // linker_override
        false,                                                   // no_skills
        false,                                                   // no_editor_setup
        true,                                                    // no_security_summary
        false,                                                   // auto_build
        None, // target_set: doctor is single-project
        None, // direct_versions_out: doctor does not finalize placeholders
        None, // script_policy_override: `lpm doctor` does not expose policy flags
        None, // advisor_override: `lpm doctor` does not expose `--advisor`
        None, // min_release_age_override: `lpm doctor` uses the package.json/global/default chain
        crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm doctor` enforces drift like a normal install
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(), // verify-policy: doctor's auto-fix install honors env + config posture chain
        // doctor's auto-fix install does not
        // surface its own sandbox-mode flags. Falls through the
        // env / config / default chain.
        false, // strict_sandbox
        false, // no_sandbox
    )
    .await
}

/// Fix: regenerate `lpm.lockb` from `lpm.lock`.
fn fix_binary_lockfile(project_dir: &Path) -> Result<(), String> {
    let lock_path = project_dir.join("lpm.lock");
    if !lock_path.exists() {
        return Err("lpm.lock not found — cannot regenerate lpm.lockb".into());
    }
    let lf = lpm_lockfile::Lockfile::read_from_file(&lock_path)
        .map_err(|e| format!("read lpm.lock failed: {e}"))?;
    let lockb = project_dir.join("lpm.lockb");
    lpm_lockfile::binary::write_binary(&lf, &lockb)
        .map_err(|e| format!("write lpm.lockb failed: {e}"))
}

/// Fix: ensure `.gitattributes` marks `lpm.lockb` as binary.
fn fix_gitattributes(project_dir: &Path) -> Result<(), String> {
    lpm_lockfile::ensure_gitattributes(project_dir)
        .map_err(|e| format!(".gitattributes update failed: {e}"))
}

/// Check if lockfile dependencies match package.json dependencies.
///
/// Reads dep names from package.json and checks if they all appear in lpm.lock.
/// Detects "lockfile out of date" drift.
fn check_deps_in_sync(project_dir: &Path) -> Option<Check> {
    let pkg_json_path = project_dir.join("package.json");
    let lockfile_path = project_dir.join("lpm.lock");

    let pkg_content = std::fs::read_to_string(&pkg_json_path).ok()?;
    let pkg: serde_json::Value = serde_json::from_str(&pkg_content).ok()?;

    let lockfile = lpm_lockfile::Lockfile::read_from_file(&lockfile_path).ok()?;

    // Collect all dep names from package.json
    let mut declared_deps: Vec<String> = Vec::new();
    if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) {
        for key in deps.keys() {
            declared_deps.push(key.clone());
        }
    }
    if let Some(deps) = pkg.get("devDependencies").and_then(|d| d.as_object()) {
        for key in deps.keys() {
            declared_deps.push(key.clone());
        }
    }

    if declared_deps.is_empty() {
        return None; // No deps to check
    }

    // Check which deps are missing from lockfile using proper lockfile parsing
    let mut missing: Vec<&str> = Vec::new();
    for dep in &declared_deps {
        if lockfile.find_package(dep).is_none() {
            missing.push(dep);
        }
    }

    if missing.is_empty() {
        Some(Check::pass(
            &doctor_catalog::DEPS_SYNC_CLEAN,
            "lockfile matches package.json",
        ))
    } else if missing.len() <= 3 {
        Some(Check::warn(
            &doctor_catalog::DEPS_SYNC_DRIFT,
            &format!(
                "lockfile missing: {} — run: lpm install",
                missing.join(", ")
            ),
        ))
    } else {
        Some(Check::warn(
            &doctor_catalog::DEPS_SYNC_DRIFT,
            &format!(
                "{} deps not in lockfile ({}, ...) — run: lpm install",
                missing.len(),
                missing[..2].join(", ")
            ),
        ))
    }
}

/// Validate lpm.json structure and known fields.
///
/// Checks:
/// - Valid JSON syntax
/// - Known top-level fields (runtime, env, tasks, tools, services, tunnel, publish, https)
/// - runtime.node is a valid version spec
/// - tasks have valid structure (command, dependsOn, cache, outputs, inputs, env)
/// - tools reference known plugins
/// - services have required command field
/// - Falls back to serde deserialization for type-level validation
fn validate_lpm_json(project_dir: &Path) -> Option<Check> {
    let lpm_json_path = project_dir.join("lpm.json");
    if !lpm_json_path.exists() {
        return None; // No lpm.json is fine — it's optional
    }

    let content = match std::fs::read_to_string(&lpm_json_path) {
        Ok(c) => c,
        Err(e) => {
            return Some(Check::fail(
                &doctor_catalog::LPM_JSON_UNREADABLE,
                &format!("cannot read: {e}"),
            ));
        }
    };

    // 1. Valid JSON?
    let doc: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return Some(Check::fail(
                &doctor_catalog::LPM_JSON_INVALID_SYNTAX,
                &format!("invalid JSON at line {} — {}", e.line(), e),
            ));
        }
    };

    let obj = match doc.as_object() {
        Some(o) => o,
        None => {
            return Some(Check::fail(
                &doctor_catalog::LPM_JSON_NOT_OBJECT,
                "must be a JSON object, not an array or primitive",
            ));
        }
    };

    let mut warnings: Vec<String> = Vec::new();

    // 2. Check for unknown top-level fields
    let known_fields = [
        "runtime", "env", "tasks", "tools", "services", "tunnel", "publish", "https",
    ];
    for key in obj.keys() {
        if !known_fields.contains(&key.as_str()) {
            warnings.push(format!("unknown field \"{key}\""));
        }
    }

    // 3. Validate runtime section
    if let Some(runtime) = obj.get("runtime") {
        if let Some(runtime_obj) = runtime.as_object() {
            for (rt_name, rt_value) in runtime_obj {
                if rt_name != "node" {
                    warnings.push(format!(
                        "runtime \"{rt_name}\" not yet supported (only \"node\")"
                    ));
                }
                if !rt_value.is_string() {
                    warnings.push(format!("runtime.{rt_name} must be a string version spec"));
                }
            }
        } else {
            warnings.push("\"runtime\" must be an object".into());
        }
    }

    // 4. Validate tasks section
    if let Some(tasks) = obj.get("tasks") {
        if let Some(tasks_obj) = tasks.as_object() {
            let known_task_fields = ["command", "dependsOn", "cache", "outputs", "inputs", "env"];
            for (task_name, task_value) in tasks_obj {
                if let Some(task_obj) = task_value.as_object() {
                    for key in task_obj.keys() {
                        if !known_task_fields.contains(&key.as_str()) {
                            warnings.push(format!("tasks.{task_name}: unknown field \"{key}\""));
                        }
                    }
                    // cache must be bool
                    if let Some(cache) = task_obj.get("cache")
                        && !cache.is_boolean()
                    {
                        warnings.push(format!("tasks.{task_name}.cache must be a boolean"));
                    }
                    // outputs and inputs must be arrays of strings
                    for field in ["outputs", "inputs"] {
                        if let Some(arr) = task_obj.get(field)
                            && !arr.is_array()
                        {
                            warnings.push(format!("tasks.{task_name}.{field} must be an array"));
                        }
                    }
                    // dependsOn must be array of strings
                    if let Some(deps) = task_obj.get("dependsOn")
                        && !deps.is_array()
                    {
                        warnings.push(format!("tasks.{task_name}.dependsOn must be an array"));
                    }
                } else {
                    warnings.push(format!("tasks.{task_name} must be an object"));
                }
            }
        } else {
            warnings.push("\"tasks\" must be an object".into());
        }
    }

    // 5. Validate tools section
    if let Some(tools) = obj.get("tools") {
        if let Some(tools_obj) = tools.as_object() {
            let known_tools: Vec<&str> = lpm_plugin::registry::list_plugins()
                .iter()
                .map(|p| p.name)
                .collect();
            for (tool_name, tool_value) in tools_obj {
                if !known_tools.contains(&tool_name.as_str()) {
                    warnings.push(format!(
                        "tools.{tool_name}: unknown plugin (available: {})",
                        known_tools.join(", ")
                    ));
                }
                if !tool_value.is_string() {
                    warnings.push(format!("tools.{tool_name} must be a version string"));
                }
            }
        } else {
            warnings.push("\"tools\" must be an object".into());
        }
    }

    // 6. Validate services section
    if let Some(services) = obj.get("services") {
        if let Some(services_obj) = services.as_object() {
            for (svc_name, svc_value) in services_obj {
                if let Some(svc_obj) = svc_value.as_object() {
                    if !svc_obj.contains_key("command") {
                        warnings.push(format!(
                            "services.{svc_name}: missing required \"command\" field"
                        ));
                    }
                } else {
                    warnings.push(format!("services.{svc_name} must be an object"));
                }
            }
        } else {
            warnings.push("\"services\" must be an object".into());
        }
    }

    // Also try parsing with the actual struct to catch serde errors
    if let Err(e) = serde_json::from_str::<lpm_runner::lpm_json::LpmJsonConfig>(&content) {
        warnings.push(format!("schema error: {e}"));
    }

    if warnings.is_empty() {
        Some(Check::pass(&doctor_catalog::LPM_JSON_VALID, "valid"))
    } else if warnings.len() == 1 {
        Some(Check::warn(
            &doctor_catalog::LPM_JSON_SCHEMA_WARNINGS,
            &warnings[0],
        ))
    } else {
        Some(Check::warn(
            &doctor_catalog::LPM_JSON_SCHEMA_WARNINGS,
            &format!("{} issues: {}", warnings.len(), warnings.join("; ")),
        ))
    }
}

/// Run the shared manifest-compat detector against the workspace root
/// manifest and surface each finding as its own coded `Check::warn`.
///
/// Source of truth: [`lpm_workspace::PackageJson::manifest_compat_issues`].
/// The same detector drives the install-time stderr warnings emitted
/// from `engine_check::enforce`, so the human surface and the JSON
/// surface always agree.
///
/// Returns an empty Vec when there are no issues, when there's no
/// workspace root (`lpm add` plain-source-copy edge case), or when the
/// manifest is unreadable / malformed (other doctor checks already
/// flag those — adding a duplicate failure here would be noise).
///
/// Each issue's `code` is preserved verbatim as the `Check.code`, so
/// `lpm doctor --json` consumers can match on `pnpm_overrides_drift`,
/// `engines_pnpm_ignored`, etc.
fn check_manifest_compat(project_dir: &Path) -> Vec<Check> {
    // Mirror engine_check's "workspace root is the gate" semantics: a
    // member-dir invocation walks up to the root, but a single-package
    // project just reads its own manifest.
    let root_pkg = match lpm_workspace::discover_workspace(project_dir) {
        Ok(Some(ws)) => ws.root_package,
        Ok(None) => match lpm_workspace::read_package_json(&project_dir.join("package.json")) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        },
        Err(_) => return Vec::new(),
    };

    root_pkg
        .manifest_compat_issues()
        .into_iter()
        .filter_map(|issue| {
            let entry = match doctor_catalog::manifest_compat_entry(issue.code) {
                Some(entry) => entry,
                None => {
                    // Orphan code: lpm-workspace declared a new
                    // manifest-compat code without a matching CLI-side
                    // wrapper in `MANIFEST_COMPAT_ENTRIES`. The
                    // cross-crate parity test in `lpm-cli`
                    // (`manifest_compat_entries_cover_workspace_catalog`)
                    // pins this at unit-test time; the `debug_assert!`
                    // here is a runtime tripwire so debug builds fail
                    // loudly if the parity test is ever bypassed.
                    debug_assert!(
                        false,
                        "orphan manifest-compat code `{}` — \
                         `lpm_workspace::MANIFEST_COMPAT_CATALOG` declares it \
                         but `lpm_cli::doctor_catalog::MANIFEST_COMPAT_ENTRIES` \
                         is missing the corresponding `pub static CheckEntry` \
                         wrapper. Add the wrapper or `lpm doctor` will \
                         silently drop the issue.",
                        issue.code,
                    );
                    return None;
                }
            };
            let detail = format!("{}. {}", issue.detail, issue.remediation);
            let check = match issue.severity {
                lpm_workspace::ManifestCompatSeverity::Warn => Check::warn(entry, &detail),
                lpm_workspace::ManifestCompatSeverity::Info => Check::pass(entry, &detail),
            };
            Some(check)
        })
        .collect()
}

// ─── global-installs health checks ─────────────────────

/// Top-level entry for the global health checks. Returns an empty Vec
/// if `~/.lpm/global/` doesn't exist (fresh machine / project-only
/// user) — doctor shouldn't invent checks for features the user hasn't
/// touched.
///
/// Each check has its own function so individual checks can be
/// unit-tested against a synthetic `LpmRoot` without running the whole
/// `doctor::run` pipeline.
fn check_global_installs() -> Vec<Check> {
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

    // 16b. (L37) Shim targets — does the symlink actually point at the
    //      expected install-root bin? Pre-fix doctor only verified
    //      that the *filename* in `~/.lpm/bin` matched a manifest
    //      command/alias name. A stale rollback shim that kept its
    //      filename but had a wrong target (pointing at a deleted
    //      install root, or — worst case — a same-user PATH hijack)
    //      passed as `global_shims_clean`. Unix-only today; Windows
    //      shim triples are scripts, not symlinks, and need a
    //      separate parser (tracked as a follow-up).
    #[cfg(unix)]
    out.push(check_global_shim_targets(&root, &manifest));

    // 17. Install-root consistency.
    out.push(check_install_root_consistency(&root, &manifest));

    // 18. (L39) Global trusted-dependencies state. A malformed /
    //     future-schema trust file can break `lpm install -g` (via
    //     synthetic `lpm.trustedDependencies`) and `lpm approve-scripts
    //     --global`; pre-fix doctor never read the file so those
    //     failures looked unexplained.
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

    // L38: structural validation beyond TOML parseability.
    //
    // Check each row's invariants the install + recovery pipelines
    // actually depend on. The TOML parser is permissive (it'll accept
    // any string for `root`); install/recovery/uninstall use the
    // L47 `validated_install_root_relative` shape check at write
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
        if let Err(reason) = lpm_global::validated_install_root_relative(&global_root, &entry.root)
        {
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

/// L39: read `~/.lpm/global/trusted-dependencies.json` and report
/// presence + approval count + parse health. A malformed or
/// future-schema trust file breaks `lpm install -g` (via the
/// synthetic `lpm.trustedDependencies` projection in
/// `install_global::synthesize_pkg_json`) and `lpm approve-scripts
/// --global`. Pre-fix doctor never touched the file, so a corrupt
/// trust file looked like an unexplained install failure later.
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

/// L37: verify each manifest-owned shim in `~/.lpm/bin` is a symlink
/// pointing at the expected `<install-root>/node_modules/.bin/<bin>`.
///
/// Unix-only — Windows shim artifacts are `.cmd`/`.ps1`/bash-shim
/// scripts that exec the target via a baked-in path string, so
/// verifying them needs a parser per shim format (tracked as a
/// follow-up to L37). The orphaned-filename check already covers the
/// stale-artifact-by-name shape on Windows.
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
            // structural problem; L38 surfaces it. Skip the target
            // check here so we don't double-fail.
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
    // Audit: finding 2 (Medium): use `validate_install_root`, the
    // authoritative predicate the install pipeline + recovery both
    // rely on. Pre-fix, Check 17 only checked `.lpm-install-ready`
    // presence — that's strictly weaker than what recovery would do.
    // A half-corrupted install (marker present but a declared bin
    // target deleted, or lockfile truncated) would be reported
    // healthy by doctor, then fail at the next `lpm install -g`
    // attempt that tried to roll it forward.
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
    for (name, entry) in &manifest.packages {
        let install_root = root.global_root().join(&entry.root);
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
                "{} root{} healthy (marker + bin targets + lockfile validated)",
                manifest.packages.len(),
                if manifest.packages.len() == 1 {
                    ""
                } else {
                    "s"
                },
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

/// close-out lifecycle-script policy + sandbox
/// surface checks.
///
/// Entries:
///
/// 18. **Sandbox availability probe.** Does the current platform
///     have a functional [`lpm_sandbox`] backend for
///     [`SandboxMode::Enforce`]? Constructs a synthetic spec and
///     calls [`lpm_sandbox::new_for_platform`], then classifies
///     the outcome:
///     - **macOS / Linux with a recent kernel** → `pass` — Seatbelt
///       or landlock is available; triage auto-execution and
///       `lpm rebuild` under every policy can contain lifecycle
///       scripts.
///     - **Windows** → `warn` with the pointer.
///       Scripts still run today (`--no-sandbox` is the 46.0
///       interim — rework collapsed the legacy
///       `--unsafe-full-env` partner), but without
///       containment — the user needs to know that
///       `script-policy = "triage"` or `allow` is effectively
///       opting out of the sandbox floor on Windows until 46.1.
///     - **Linux with an old kernel** → `warn` with the landlock
///       kernel-version requirement. Same containment gap as
///       Windows for the specific versions.
///
/// 19. **Scope-boundary note.** The 46.0 script-policy surface
///     covers **project installs only**. Global installs
///     (`lpm install -g`) use a separate trust store at
///     `~/.lpm/global/trusted-dependencies.json`; this surface does not
///     apply the sandbox probe / tier classification / version
///     diff to that path. The note only fires when the user has at
///     least one global install (otherwise the scope limit is
///     irrelevant to them and would be noise).
///
/// Placed AFTER the global-installs block so the scope-boundary
/// note has the same firing condition (`~/.lpm/global/` exists
/// with content) as the related checks it contextualizes.
/// Emit the doctor row for the resolved Sigstore verification
/// `EnforceMode`. Reads the env var + `~/.lpm/config.toml` once via
/// the same resolver the install pipeline uses, so the doctor view
/// matches what an install would actually do.
///
/// Three outcomes — exactly one fires per run:
/// - `deny` (default or explicit) → pass.
/// - `warn` → warn with the re-enable hint.
/// - `off` → warn with the re-enable hint.
fn check_sigstore_verify_posture() -> Check {
    use crate::provenance_fetch::{EnforceMode, EnforceModeSource};
    let cfg = super::config::GlobalConfig::load();
    let (mode, source) = EnforceMode::resolve_from_chain(
        std::env::var("LPM_PROVENANCE_ENFORCE").ok().as_deref(),
        || cfg.get_sigstore_verify(),
    );
    let source_label = match source {
        EnforceModeSource::Env => "LPM_PROVENANCE_ENFORCE env",
        EnforceModeSource::Config => "[sigstore].verify in ~/.lpm/config.toml",
        EnforceModeSource::Default => "default",
    };
    match mode {
        EnforceMode::Deny => Check::pass(
            &doctor_catalog::SIGSTORE_VERIFY_ENFORCED,
            &format!("deny (source: {source_label})"),
        ),
        EnforceMode::Warn => Check::warn(
            &doctor_catalog::SIGSTORE_VERIFY_WARN_MODE,
            &format!(
                "warn (source: {source_label}) — verifier rejections only log; \
                 install still proceeds. {}",
                source.re_enable_hint(),
            ),
        ),
        EnforceMode::Off => Check::warn(
            &doctor_catalog::SIGSTORE_VERIFY_DISABLED,
            &format!(
                "off (source: {source_label}) — every Sigstore attestation will be \
                 IGNORED. {}",
                source.re_enable_hint(),
            ),
        ),
    }
}

fn check_script_policy_surface() -> Vec<Check> {
    let mut out = Vec::new();

    // 18. Sandbox availability.
    out.push(probe_sandbox_backend());

    // the scope-boundary note that previously fired here
    // when globals were present is gone — `lpm install -g` now honors
    // the same script-policy / sandbox / cooldown / drift gates as
    // project installs, so the boundary it described no longer exists.
    // The matching `POLICY_SCOPE_PROJECT_ONLY` doctor-catalog entry was
    // also removed.

    // 20. Force-security-floor kill-switch
    // status. Only surfaces when the flag is set — unset is the
    // default for every user who hasn't explicitly opted into the
    // kill-switch, and we don't clutter clean output with it. When
    // set, reports the count of suspended approvals in the current
    // project (if a package.json is present) so users can see what
    // the flag is holding back.
    if let Some(check) = check_force_security_floor() {
        out.push(check);
    }

    out
}

/// report the force-security-floor kill-switch
/// state. Returns `None` when the flag is unset (the default), so
/// clean output stays clean. Returns `Some(Check::warn(...))` when
/// set, naming the count of suspended approvals if a project
/// `package.json` is present — empty project or no approvals produces
/// a no-count variant of the same message.
fn check_force_security_floor() -> Option<Check> {
    let global = crate::commands::config::GlobalConfig::load();
    if !global.get_bool("force-security-floor").unwrap_or(false) {
        return None;
    }

    let suspended_count = count_suspended_approvals_in_cwd();

    let detail = match suspended_count {
        None => "enabled — no `package.json` in current directory, so suspended-approval \
             count is not available. Run `lpm config unset force-security-floor` to reactivate \
             approvals (any loosening CLI flags are also currently suppressed)."
            .to_string(),
        Some(0) => "enabled — the current project has no approvals in \
             `package.json > lpm > trustedDependencies` to suspend. Run \
             `lpm config unset force-security-floor` to remove the kill-switch."
            .to_string(),
        Some(n) => format!(
            "enabled — {n} approval(s) in `package.json > lpm > trustedDependencies` \
             are currently suspended (scripts for these packages will NOT run until \
             the kill-switch is unset). Run `lpm config unset force-security-floor` \
             to reactivate all {n} approval(s) without re-review."
        ),
    };
    Some(Check::warn(
        &doctor_catalog::POLICY_FORCE_SECURITY_FLOOR,
        &detail,
    ))
}

/// Count the approval entries in the current project's
/// `package.json > lpm > trustedDependencies`.
///
/// Returns `None` when `./package.json` is missing or unreadable
/// (no project context, so the count is unknowable). Returns
/// `Some(n)` otherwise — including `Some(0)` for a project with
/// no approvals, which is a meaningfully different state from
/// "no project."
///
/// Counts both the Legacy (`Vec<String>`) and Rich
/// (`Map<String, TrustedDependencyBinding>`) forms, matching the
/// check that [`crate::commands::rebuild::evaluate_trust`]
/// performs at install time.
fn count_suspended_approvals_in_cwd() -> Option<usize> {
    let pkg_json = std::env::current_dir().ok()?.join("package.json");
    let content = std::fs::read_to_string(&pkg_json).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let trusted = parsed.get("lpm")?.get("trustedDependencies")?;
    match trusted {
        serde_json::Value::Array(arr) => Some(arr.len()),
        serde_json::Value::Object(obj) => Some(obj.len()),
        _ => Some(0),
    }
}

/// Probe the sandbox backend for `SandboxMode::Enforce` on this
/// platform. Runs in-memory (macOS) or via a single benign
/// landlock ruleset-create syscall (Linux); no persistent I/O.
///
/// the probe loads the user's `[sandbox] allow-degraded`
/// config (project lpm.toml + global ~/.lpm/config.toml — same
/// chain the install pipeline uses) so the doctor surface reports
/// the SAME posture the next `lpm install` will actually
/// construct. Without that, a user who opted into degraded posture
/// on a kernel < 6.7 would see "strict / fail" in doctor while
/// their installs silently run under V1 (or vice-versa).
fn probe_sandbox_backend() -> Check {
    use lpm_sandbox::{
        SandboxError, SandboxMode, SandboxPosture, SandboxSpec, new_for_platform_with_options,
    };

    let tmpdir = std::env::temp_dir();
    let home = dirs::home_dir().unwrap_or_else(|| tmpdir.clone());
    let spec = SandboxSpec {
        // `validate_spec` requires absolute paths + non-empty
        // identity. Nothing reads from these; the probe only
        // checks whether the backend can be constructed for
        // this platform + mode.
        package_dir: tmpdir.join("lpm-doctor-sandbox-probe"),
        project_dir: tmpdir.join("lpm-doctor-sandbox-probe"),
        package_name: "lpm-doctor-probe".into(),
        package_version: "0.0.0".into(),
        store_root: home.join(".lpm").join("store"),
        home_dir: home.clone(),
        tmpdir: tmpdir.clone(),
        secret_read_allow: Vec::new(),
        extra_write_dirs: Vec::new(),
    };

    // load the `[sandbox] allow-degraded` knob from
    // `<cwd>/lpm.toml` + `~/.lpm/config.toml`. The project-side read
    // uses the current working directory — that's what `lpm doctor`
    // is reporting on, and matches the install pipeline's
    // resolution against the same directory.
    //
    // A failed config load surfaces as `sandbox_probe_failed`
    // EXPLICITLY rather than getting silently defaulted to strict.
    // A broken `lpm.toml` / `~/.lpm/config.toml` makes the real
    // install fail at config-load time; doctor's job is to surface
    // that on the same machine, NOT to hide it behind a default-
    // strict posture the install will never actually reach. Only
    // `current_dir()` failing (no cwd resolvable, e.g. running
    // from a deleted directory) falls back to the strict default —
    // there's no config to parse in that case.
    let (sandbox_options, resolved_mode) = match std::env::current_dir() {
        // route through the precedence chain so
        // `LPM_STRICT_SANDBOX=1` and `[sandbox] mode` flow through
        // the doctor probe identically to the install pipeline.
        Ok(cwd) => match crate::sandbox_config::resolve_sandbox_mode_from_chain(&cwd, false, false)
        {
            Ok(pair) => pair,
            Err(e) => {
                return Check::fail(
                    &doctor_catalog::SANDBOX_PROBE_FAILED,
                    &format!(
                        "could not load sandbox config: {e}. Doctor refuses to default \
                         this to strict — the same broken config will fail your next \
                         `lpm install`. Fix `lpm.toml` / `~/.lpm/config.toml` and re-run."
                    ),
                );
            }
        },
        Err(_) => (
            lpm_sandbox::SandboxOptions::default(),
            crate::sandbox_config::ResolvedSandboxMode::Default,
        ),
    };

    // rework follow-up : when the
    // resolved mode is `None` (`[sandbox] mode = "none"` in
    // `~/.lpm/config.toml` / `./lpm.toml`, persisted by
    // `lpm config sandbox --set none`), the install pipeline runs
    // [`SandboxMode::Disabled`] — so doctor must report that posture
    // directly instead of probing `Enforce` and reporting whatever
    // the host's backend happens to support. Pre-fix this branch
    // was unreachable in normal use because doctor always probed
    // Enforce; users would see "default mode: filesystem-write
    // containment …" even after running `lpm config sandbox --set
    // none`, which contradicts the install behaviour.
    if matches!(
        resolved_mode,
        crate::sandbox_config::ResolvedSandboxMode::None
    ) {
        let os = std::env::consts::OS;
        return Check::warn(
            &doctor_catalog::SANDBOX_DISABLED_BY_USER,
            &format!(
                "sandbox DISABLED on {os} via `[sandbox] mode = \"none\"` (set by \
                 `lpm config sandbox --set none` or directly in `~/.lpm/config.toml` / \
                 `./lpm.toml`). Lifecycle scripts will run WITHOUT filesystem / env / \
                 network containment. Re-enable the default posture via \
                 `lpm config sandbox --set default`."
            ),
        );
    }

    match new_for_platform_with_options(spec, SandboxMode::Enforce, sandbox_options) {
        Ok(sb) => {
            let backend = sb.backend_name();
            let os = std::env::consts::OS;
            // on Windows, the
            // `windows-il` backend is now the FALLBACK path —
            // the post-rework happy path is `windows-appcontainer`,
            // which delivers full strict (filesystem-write +
            // outbound network) when the
            // `lpm-sandbox-helper.exe` companion binary is sitting
            // next to `lpm.exe`. If the user has fallen back to
            // Low IL, they're missing the helper (npm install
            // corruption, manual binary fetch that skipped the
            // helper, or — in test contexts — `cargo run`/`cargo
            // test` where the helper isn't placed sibling to the
            // calling binary). Surface that as a Warn so the user
            // knows strict mode is unreachable on this install
            // until the helper comes back.
            if os == "windows" && backend == "windows-il" {
                return Check::warn(
                    &doctor_catalog::SANDBOX_HELPER_MISSING,
                    "windows-il available on windows — falling back from AppContainer \
                     because `lpm-sandbox-helper.exe` is not located next to \
                     `lpm.exe`. The Low IL backend contains filesystem \
                     writes but does NOT deny outbound network. Reinstall lpm \
                     (`@lpm-registry/cli`) to restore the helper, or override the \
                     helper location via `LPM_SANDBOX_HELPER=<path>`. With the helper \
                     present, `lpm doctor` reports `windows-appcontainer` and \
                     strict mode is available.",
                );
            }
            match sb.posture() {
                SandboxPosture::Default => Check::pass(
                    &doctor_catalog::SANDBOX_AVAILABLE,
                    &format!(
                        "{backend} available on {os} — default mode: filesystem-write \
                         containment + env scrubbing, outbound network ALLOWED. Enable \
                         strict mode (also denies outbound network) via \
                         `lpm config sandbox --set strict`, `--strict-sandbox` per-command, \
                         or `LPM_STRICT_SANDBOX=1` in env."
                    ),
                ),
                SandboxPosture::Strict => {
                    // Network-denial coverage is platform-asymmetric:
                    // - macOS Seatbelt's `(deny default)` covers every
                    //   socket family unconditionally.
                    // - Windows AppContainer denies
                    //   every socket family via the WFP layer once the
                    //   capability list is empty — same coverage shape
                    //   as macOS Seatbelt.
                    // - Linux landlock V4 + seccomp-bpf
                    //   layered together: landlock denies BindTcp +
                    //   ConnectTcp, seccomp denies direct
                    //   socket(AF_INET|AF_INET6, SOCK_DGRAM|SOCK_RAW)
                    //   + AF_PACKET + AF_NETLINK. AF_UNIX intentionally
                    //   allowed (legitimate IPC); resolver-mediated DNS
                    //   stays host-dependent.
                    let net_coverage = if os == "macos" {
                        "full outbound network denial (all socket families)"
                    } else if backend == "windows-appcontainer" {
                        "full outbound network denial via AppContainer + WFP \
                         (all socket families)"
                    } else {
                        "outbound TCP denial (landlock V4: BindTcp + ConnectTcp) + \
                         direct UDP / raw / AF_PACKET / AF_NETLINK denial \
                         (seccomp-bpf, 1); AF_UNIX allowed for IPC"
                    };
                    Check::pass(
                        &doctor_catalog::SANDBOX_AVAILABLE,
                        &format!(
                            "{backend} available on {os} — strict mode: enforces \
                             filesystem-write containment + {net_coverage}"
                        ),
                    )
                }
                SandboxPosture::Degraded {
                    kernel,
                    abi,
                    missing,
                } => {
                    // both Linux
                    // (kernel < 6.7 + allow-degraded) and Windows
                    // (`windows-il` Low IL FALLBACK when the
                    // `lpm-sandbox-helper.exe` AppContainer launcher
                    // is missing + allow-degraded) reach this arm.
                    // The `abi` field carries the discriminator
                    // (`v1` = Linux landlock V1 fallback; `low-il`
                    // = Windows Mandatory Integrity Control
                    // fallback). Pick a platform-honest message —
                    // a single Linux-shaped string would lie about
                    // the remediation on Windows.
                    //
                    // On Windows the strict-mode cause is now
                    // "the helper binary that delivers AppContainer
                    // strict isn't sitting next to lpm.exe." That's
                    // an npm-install corruption symptom — reinstall
                    // is the fix.
                    let cause_and_fix = if abi == "low-il" {
                        "user requested strict but `lpm-sandbox-helper.exe` is not located \
                         next to `lpm.exe`; the AppContainer backend (filesystem + \
                         outbound-network containment) needs the helper to \
                         deliver strict mode. Falling back to Low IL backend, \
                         which contains filesystem writes but does NOT deny outbound \
                         network. Reinstall lpm (`@lpm-registry/cli`) to restore the helper, \
                         or override the helper location via `LPM_SANDBOX_HELPER=<path>`. \
                         Switch to `lpm config sandbox --set default` to drop the strict \
                         request and silence this warning."
                    } else {
                        "user requested strict but kernel can't deliver V4; enforces \
                         filesystem only. Upgrade the kernel to 6.7+ to restore strict \
                         containment, or switch to `lpm config sandbox --set default` to \
                         drop the strict request and silence this warning."
                    };
                    Check::warn(
                        &doctor_catalog::SANDBOX_DEGRADED,
                        &format!(
                            "{backend} available on {os} — DEGRADED posture (kernel \
                             {kernel}, abi {abi}); {cause_and_fix} missing={missing}."
                        ),
                    )
                }
                SandboxPosture::Disabled => Check::warn(
                    &doctor_catalog::SANDBOX_AVAILABLE,
                    &format!(
                        "{backend} returned Disabled posture on {os} — unexpected for \
                         SandboxMode::Enforce. File an issue with `lpm doctor --json` output."
                    ),
                ),
            }
        }
        Err(SandboxError::UnsupportedPlatform {
            platform,
            remediation,
        }) => Check::warn(
            &doctor_catalog::SANDBOX_UNSUPPORTED_PLATFORM,
            &format!(
                "unavailable on {platform} — {remediation}. Lifecycle scripts under \
                 `script-policy = \"triage\"` or `\"allow\"`, and any `lpm rebuild` \
                 invocation, run without filesystem containment on this platform — \
                 sandbox enforcement isn't supported here yet."
            ),
        ),
        Err(SandboxError::KernelTooOld {
            detected,
            required,
            remediation,
        }) => Check::warn(
            &doctor_catalog::SANDBOX_KERNEL_TOO_OLD,
            &format!(
                "Linux kernel {detected} is below the landlock requirement \
                 ({required}+). {remediation}"
            ),
        ),
        Err(e) => Check::fail(
            &doctor_catalog::SANDBOX_PROBE_FAILED,
            &format!(
                "probe failed: {e}. This is unexpected — the synthetic spec is \
                 well-formed; file an issue with `lpm doctor --json` output."
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_pass_sets_passed_true() {
        let c = Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "ok");
        assert_eq!(c.code(), "registry_reachable");
        assert!(c.passed);
        assert!(matches!(c.severity, Severity::Pass));
    }

    #[test]
    fn check_fail_sets_passed_false() {
        let c = Check::fail(&doctor_catalog::REGISTRY_UNREACHABLE, "bad");
        assert_eq!(c.code(), "registry_unreachable");
        assert!(!c.passed);
        assert!(matches!(c.severity, Severity::Fail));
    }

    #[test]
    fn check_warn_sets_passed_true_but_severity_warn() {
        let c = Check::warn(&doctor_catalog::DEPS_SYNC_DRIFT, "meh");
        assert_eq!(c.code(), "deps_sync_drift");
        assert!(c.passed);
        assert!(matches!(c.severity, Severity::Warn));
    }

    /// Codes flow from the catalog entry, never the call site.
    /// Verifies every constructor exposes a non-empty code via the
    /// `code()` method, mirroring the contract pinned by the
    /// `lpm doctor --json` workflow test.
    #[test]
    fn check_constructors_expose_non_empty_code_from_catalog() {
        let p = Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "");
        let f = Check::fail(&doctor_catalog::AUTH_INVALID, "");
        let w = Check::warn(&doctor_catalog::DEPS_SYNC_DRIFT, "");
        for c in [&p, &f, &w] {
            assert!(!c.code().is_empty(), "every check needs a non-empty code");
        }
    }

    #[test]
    fn sandbox_probe_emits_known_code() {
        // Pin the codes the sandbox probe is allowed to emit so the
        // automation contract for this check stays stable across
        // platforms / refactors. adds `sandbox_degraded`
        // for the V1-fallback path; the follow-up adds
        // `sandbox_disabled_by_user` for the persistent `mode =
        // "none"` path; It adds `sandbox_helper_missing`
        // for the Windows AppContainer-helper-not-found fallback;
        // the other four codes are pre-existing.
        let c = probe_sandbox_backend();
        let allowed = [
            "sandbox_available",
            "sandbox_helper_missing",
            "sandbox_degraded",
            "sandbox_disabled_by_user",
            "sandbox_unsupported_platform",
            "sandbox_kernel_too_old",
            "sandbox_probe_failed",
        ];
        assert!(
            allowed.contains(&c.code()),
            "unexpected sandbox probe code: {} (allowed: {:?})",
            c.code(),
            allowed
        );
    }

    // ── close-out sandbox probe + scope-boundary ──

    /// Universal smoke test: the sandbox probe must always return a
    /// `Check` on every platform the CI matrix + local dev runs on
    /// (macOS, Linux, Windows). Pins the contract that the probe
    /// never panics regardless of backend availability — a fail
    /// result on a misbehaving platform is still a Check, not a
    /// crash. The per-platform severity assertions below narrow
    /// this further; this test is the "always produces output"
    /// floor.
    #[test]
    fn sandbox_probe_always_returns_a_check() {
        let c = probe_sandbox_backend();
        assert_eq!(c.name(), "Sandbox");
        // Severity ∈ {Pass, Warn, Fail}. All three are acceptable
        // depending on platform + kernel; what matters is that the
        // probe didn't panic and produced a named Check.
        assert!(
            !c.detail.is_empty(),
            "probe must emit a non-empty detail line"
        );
    }

    /// On macOS, the probe must return Pass with detail naming
    /// `seatbelt`. CI's macOS runners have Seatbelt available by
    /// construction; developer machines do too.
    #[cfg(target_os = "macos")]
    #[test]
    fn sandbox_probe_on_macos_passes_with_seatbelt_backend() {
        let c = probe_sandbox_backend();
        assert!(
            matches!(c.severity, Severity::Pass),
            "macOS sandbox probe should pass — expected Seatbelt available. detail={}",
            c.detail
        );
        assert!(
            c.detail.contains("seatbelt"),
            "detail must name the backend so users can debug. detail={}",
            c.detail
        );
    }

    /// On Linux, the probe returns Pass (kernel >= 5.13 with
    /// landlock) OR Warn (older kernel). Either outcome is a
    /// meaningful Check — but never a Fail, because an unsupported
    /// kernel on a supported platform is a warning, not a failure
    /// per the `KernelTooOld` arm.
    #[cfg(target_os = "linux")]
    #[test]
    fn sandbox_probe_on_linux_passes_or_warns_never_fails() {
        let c = probe_sandbox_backend();
        assert!(
            !matches!(c.severity, Severity::Fail),
            "Linux sandbox probe must not Fail — Pass (landlock) or \
             Warn (kernel too old) are the only acceptable outcomes. detail={}",
            c.detail
        );
    }

    /// On Windows, the active backend is determined by helper-binary
    /// presence:
    ///
    /// - **`windows-appcontainer`** when
    ///   `lpm-sandbox-helper.exe` is reachable. Pass under default,
    ///   Pass naming "AppContainer + WFP" under strict.
    /// - **`windows-il` (fallback)** when the helper
    ///   binary is missing. Warn surfaces the fallback explicitly
    ///   with the reinstall remediation, even under default — the
    ///   user has lost outbound-network containment in strict mode
    ///   and should know that.
    /// - **Warn `sandbox_disabled_by_user`** when the user has
    ///   `[sandbox] mode = "none"` persisted.
    ///
    /// A Fail here is a regression — Mandatory Integrity Control
    /// has been in every Windows release since Vista, and the AppContainer backend's
    /// AppContainer backend has no preconditions beyond
    /// "Win32_Security_Isolation surface is reachable" (Windows
    /// 8+).
    ///
    /// rework /  the `--unsafe-full-env` partner flag
    /// was collapsed into `--no-sandbox`. We keep that assertion in
    /// case a future refactor accidentally resurrects the legacy
    /// remediation string.
    #[cfg(target_os = "windows")]
    #[test]
    fn sandbox_probe_on_windows_passes_or_warns_with_known_backend_name() {
        let c = probe_sandbox_backend();
        assert!(
            !matches!(c.severity, Severity::Fail),
            "Windows sandbox probe must not Fail post-rework (AppContainer + Low IL fallback \
             are both reachable on every supported Windows host). detail={}",
            c.detail
        );
        // Whichever path fired, the detail names the active backend
        // so users can route the right remediation.
        assert!(
            c.detail.contains("windows-il") || c.detail.contains("windows-appcontainer"),
            "doctor detail must name the active backend; got: {}",
            c.detail
        );
        // legacy partner flag must never appear.
        assert!(
            !c.detail.contains("--unsafe-full-env"),
            "legacy partner flag must be gone from doctor output: {}",
            c.detail
        );
    }

    /// Scope-boundary note: NOT emitted when the global manifest
    /// has no active installs (fresh machine / never used
    /// the scope-boundary note has been removed because
    /// `lpm install -g` now honors the same script-policy / sandbox /
    /// cooldown / drift gates as project installs. Doctor must NOT
    /// emit a `policy_scope_project_only` check anymore even when
    /// globals are present.
    #[test]
    fn doctor_does_not_emit_policy_scope_boundary_for_globals() {
        let tmp = tempfile::tempdir().unwrap();
        let root = lpm_common::LpmRoot::from_dir(tmp.path());
        let global_root = root.global_root();
        std::fs::create_dir_all(&global_root).unwrap();
        std::fs::write(
            global_root.join("manifest.toml"),
            r#"schema_version = 1

[packages.some-pkg]
saved_spec = "^1"
resolved = "1.0.0"
integrity = "sha512-fixture"
source = "upstream-npm"
installed_at = "T00:00:00Z"
root = "installs/some-pkg@1.0.0"
commands = []
"#,
        )
        .unwrap();
        let _env =
            crate::test_env::ScopedEnv::set([("LPM_HOME", tmp.path().as_os_str().to_owned())]);
        let out = check_script_policy_surface();
        for c in &out {
            assert_ne!(
                c.code(),
                "policy_scope_project_only",
                "scope-boundary check must no longer fire",
            );
        }
    }

    /// `check_script_policy_surface` always emits the sandbox probe
    /// (never conditional). This test pins the aggregator's contract
    /// against regression — a future refactor that accidentally
    /// gated the sandbox probe behind some condition would be caught here.
    #[test]
    fn check_script_policy_surface_always_includes_sandbox_probe() {
        let out = check_script_policy_surface();
        assert!(!out.is_empty(), "must emit at least the sandbox probe");
        assert_eq!(
            out[0].name(),
            "Sandbox",
            "sandbox probe must be the first entry so it renders \
             next to the other infrastructure checks"
        );
    }

    /// follow-up : when the user has set
    /// `[sandbox] mode = "none"` in `~/.lpm/config.toml` (via
    /// `lpm config sandbox --set none` or by hand), the doctor probe
    /// MUST report the disabled posture instead of probing
    /// `SandboxMode::Enforce` and reporting whatever the backend
    /// happens to support. Pre-fix, doctor lied about that state —
    /// it said "default mode: filesystem-write containment …" while
    /// the install pipeline was running unsandboxed.
    ///
    /// Test isolates the global config by overriding `HOME` to a
    /// tempdir and writing the wizard's on-disk shape directly. The
    /// project tier is silent (no `lpm.toml` in cwd typically), so
    /// the global tier wins.
    ///
    /// `cfg(unix)` because `dirs::home_dir()` only consults `HOME`
    /// on Unix-not-redox; on Windows it uses the Win32
    /// GetUserProfileDirectory call, so the `HOME=tempdir` override
    /// here doesn't redirect `~/.lpm/config.toml` to the tempdir.
    /// The persistent-mode-none behavior on Windows is covered
    /// indirectly by the integration tests in
    /// `tests/workflows/tests/sandbox_*` which exercise the
    /// resolver against the real per-platform config home.
    #[cfg(unix)]
    #[test]
    fn sandbox_probe_honors_persistent_mode_none_from_global_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".lpm")).unwrap();
        std::fs::write(
            home.join(".lpm").join("config.toml"),
            "[sandbox]\nmode = \"none\"\n",
        )
        .unwrap();
        // Override HOME for the duration of the probe call. The
        // resolver's `dirs::home_dir()` consults HOME on Unix; the
        // ScopedEnv mutex serialises with other tests that touch
        // process-wide env vars.
        let _env = crate::test_env::ScopedEnv::set([("HOME", home.as_os_str().to_owned())]);

        let c = probe_sandbox_backend();

        assert_eq!(
            c.code(),
            "sandbox_disabled_by_user",
            "doctor must emit the dedicated `sandbox_disabled_by_user` code so JSON \
             consumers can tell the persistent-off-mode apart from `sandbox_available` \
             / `sandbox_degraded`. got: code={} detail={}",
            c.code(),
            c.detail,
        );
        assert!(
            matches!(c.severity, Severity::Warn),
            "persistent `mode = \"none\"` is a chosen-state warning, not a pass. \
             got severity={:?}, detail={}",
            c.severity,
            c.detail,
        );
        assert!(
            c.detail.contains("DISABLED") || c.detail.contains("disabled"),
            "detail must announce the disabled posture so the user sees their \
             config decision is taking effect. got: {}",
            c.detail,
        );
        // Negative assertion that doubles as the regression pin: the
        // old buggy probe emitted "default mode: filesystem-write
        // containment …". If that string ever resurfaces under
        // `mode = "none"`, doctor is back to lying.
        assert!(
            !c.detail.contains("default mode:"),
            "pre-fix detail leaked under `mode = \"none\"` — doctor must NOT \
             claim default-mode containment when config asked for none. got: {}",
            c.detail,
        );
    }

    /// Doctor must emit the dedicated `sigstore_verify_enforced`
    /// pass row when no operator override is in scope (env unset,
    /// config absent). Default `Deny` is the recommended posture.
    /// The HOME isolation matches the sandbox-probe test pattern
    /// so the dev's `~/.lpm/config.toml` doesn't leak in.
    #[cfg(unix)]
    #[test]
    fn sigstore_posture_check_reports_enforced_under_default() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".lpm")).unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("HOME", home.as_os_str().to_owned()),
            ("LPM_PROVENANCE_ENFORCE", std::ffi::OsString::new()),
        ]);

        let c = check_sigstore_verify_posture();
        assert_eq!(c.code(), "sigstore_verify_enforced");
        assert!(matches!(c.severity, Severity::Pass));
        assert!(
            c.detail.contains("deny"),
            "detail must name the resolved mode; got: {}",
            c.detail
        );
        assert!(
            c.detail.contains("default"),
            "detail must name the source (default) so operators can trace the posture; got: {}",
            c.detail,
        );
    }

    /// `[sigstore].verify = "warn"` in the user's config → warn row
    /// with the re-enable hint. Doctor must surface the degraded
    /// posture even when no install is in flight — that's the
    /// "operator forgot they flipped the knob" mitigation the plan
    /// pins.
    #[cfg(unix)]
    #[test]
    fn sigstore_posture_check_reports_warn_mode_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".lpm")).unwrap();
        std::fs::write(
            home.join(".lpm").join("config.toml"),
            "[sigstore]\nverify = \"warn\"\n",
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("HOME", home.as_os_str().to_owned()),
            ("LPM_PROVENANCE_ENFORCE", std::ffi::OsString::new()),
        ]);

        let c = check_sigstore_verify_posture();
        assert_eq!(
            c.code(),
            "sigstore_verify_warn_mode",
            "doctor must emit the dedicated `sigstore_verify_warn_mode` code so JSON \
             consumers can tell warn-mode apart from the disabled state",
        );
        assert!(matches!(c.severity, Severity::Warn));
        assert!(
            c.detail.contains("lpm config sigstore --set deny"),
            "warn detail must point at the wizard re-enable command so operators know \
             how to tighten back; got: {}",
            c.detail,
        );
    }

    /// `LPM_PROVENANCE_ENFORCE=off` → disabled-posture warn row.
    /// Env wins over config per the precedence chain.
    #[cfg(unix)]
    #[test]
    fn sigstore_posture_check_reports_disabled_from_env_over_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".lpm")).unwrap();
        // Config says deny — env says off — env wins.
        std::fs::write(
            home.join(".lpm").join("config.toml"),
            "[sigstore]\nverify = \"deny\"\n",
        )
        .unwrap();
        let _env = crate::test_env::ScopedEnv::set([
            ("HOME", home.as_os_str().to_owned()),
            ("LPM_PROVENANCE_ENFORCE", std::ffi::OsString::from("off")),
        ]);

        let c = check_sigstore_verify_posture();
        assert_eq!(c.code(), "sigstore_verify_disabled");
        assert!(matches!(c.severity, Severity::Warn));
        assert!(
            c.detail.contains("IGNORED"),
            "detail must announce the fleet-wide opt-out posture; got: {}",
            c.detail,
        );
        assert!(
            c.detail.contains("LPM_PROVENANCE_ENFORCE"),
            "detail must point at the env re-enable knob (env was the source); got: {}",
            c.detail,
        );
    }

    #[test]
    fn warning_count_with_mixed_checks() {
        let checks = [
            Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "ok"),
            Check::warn(&doctor_catalog::DEPS_SYNC_DRIFT, "meh"),
            Check::fail(&doctor_catalog::AUTH_INVALID, "bad"),
            Check::warn(&doctor_catalog::LOCKFILE_MISSING, "meh2"),
        ];

        let warning_count = checks
            .iter()
            .filter(|c| matches!(c.severity, Severity::Warn))
            .count();
        let failed_count = checks.iter().filter(|c| !c.passed).count();
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;

        assert_eq!(warning_count, 2);
        assert_eq!(failed_count, 1);
        assert!(!no_failures); // fail check makes no_failures false
        assert!(has_warnings);
        assert!(!clean);
    }

    #[test]
    fn no_failures_true_with_warnings_but_clean_false() {
        // Warnings don't count as failures, but the run is not "clean"
        let checks = [
            Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "ok"),
            Check::warn(&doctor_catalog::DEPS_SYNC_DRIFT, "meh"),
        ];
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;

        assert!(no_failures);
        assert!(has_warnings);
        assert!(!clean);
    }

    #[test]
    fn clean_true_only_when_all_pass_no_warnings() {
        let checks = [
            Check::pass(&doctor_catalog::REGISTRY_REACHABLE, "ok"),
            Check::pass(&doctor_catalog::AUTH_VALID, "fine"),
        ];
        let no_failures = checks.iter().all(|c| c.passed);
        let has_warnings = checks.iter().any(|c| matches!(c.severity, Severity::Warn));
        let clean = no_failures && !has_warnings;

        assert!(no_failures);
        assert!(!has_warnings);
        assert!(clean);
    }

    #[test]
    fn deps_sync_uses_exact_name_matching() {
        // Bug: naive string search with `contains("name = \"a\"")` would match
        // a package named "react" if we searched for "a" because "a" appears inside "react".
        // The old code used `lock_content.contains(...)` which is too loose.
        // With proper lockfile parsing via find_package(), only exact matches work.
        let dir = tempfile::tempdir().unwrap();

        // Create package.json with dep "a"
        let pkg_json = serde_json::json!({
            "dependencies": {
                "a": "^1.0.0"
            }
        });
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap(),
        )
        .unwrap();

        // Create lockfile with "react" but NOT "a"
        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            tarball: None,
        });
        lockfile
            .write_to_file(&dir.path().join("lpm.lock"))
            .unwrap();

        let result = check_deps_in_sync(dir.path());
        let check = result.expect("should return a check");
        // "a" should be reported as missing — it is NOT in the lockfile
        assert!(
            matches!(check.severity, Severity::Warn),
            "dep 'a' should be missing from lockfile"
        );
        assert!(
            check.detail.contains("a"),
            "detail should mention missing dep 'a'"
        );
    }

    #[test]
    fn deps_sync_finds_exact_match() {
        let dir = tempfile::tempdir().unwrap();

        let pkg_json = serde_json::json!({
            "dependencies": {
                "react": "^18.0.0"
            }
        });
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap(),
        )
        .unwrap();

        let mut lockfile = lpm_lockfile::Lockfile::new();
        lockfile.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: None,
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            tarball: None,
        });
        lockfile
            .write_to_file(&dir.path().join("lpm.lock"))
            .unwrap();

        let result = check_deps_in_sync(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "react should be found in lockfile"
        );
    }

    #[test]
    fn extract_node_spec_works() {
        let detail = "not found — pinned >=22 from .nvmrc. Run: lpm use node@22";
        let spec = extract_node_spec_from_detail(detail);
        assert_eq!(spec, Some("22".to_string()));
    }

    #[test]
    fn extract_node_spec_none_when_missing() {
        let detail = "v20.0.0 (system, no version pinned)";
        let spec = extract_node_spec_from_detail(detail);
        assert!(spec.is_none());
    }

    // ── Lockfile state checks ───────────────────────────────────────────

    #[test]
    fn lockfile_check_no_lockfile_warns() {
        let dir = tempfile::tempdir().unwrap();
        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name(), "Lockfile");
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not found"));
    }

    #[test]
    fn lockfile_check_toml_only_warns_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].name(), "Lockfile");
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert_eq!(checks[1].name(), "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("missing"));
    }

    #[test]
    fn lockfile_check_both_in_sync_passes() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        // Write TOML first, then binary (so binary is newer)
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        lpm_lockfile::binary::write_binary(&lf, &dir.path().join("lpm.lockb")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert_eq!(checks[1].name(), "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Pass));
        assert!(checks[1].detail.contains("in sync, valid"));
    }

    #[test]
    fn lockfile_check_stale_binary_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        // Write binary first (older), then TOML (newer)
        lpm_lockfile::binary::write_binary(&lf, &dir.path().join("lpm.lockb")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[1].name(), "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("stale"));
    }

    #[test]
    fn lockfile_check_corrupt_binary_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        // Write corrupt binary (newer than TOML)
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(dir.path().join("lpm.lockb"), b"BADMxxxxxxxxxxxxxxxxx").unwrap();

        let checks = check_lockfile_state(dir.path());
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[1].name(), "Binary lockfile");
        assert!(matches!(checks[1].severity, Severity::Warn));
        assert!(checks[1].detail.contains("corrupt"));
    }

    // ── .gitattributes state checks ─────────────────────────────────────

    #[test]
    fn gitattributes_check_skipped_without_lockfiles() {
        let dir = tempfile::tempdir().unwrap();
        // No lpm.lock or lpm.lockb — should produce no checks
        let checks = check_gitattributes_state(dir.path());
        assert!(checks.is_empty());
    }

    #[test]
    fn gitattributes_check_missing_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        // No .gitattributes file

        let checks = check_gitattributes_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("missing"));
    }

    #[test]
    fn gitattributes_check_without_marker_warns() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::fs::write(dir.path().join(".gitattributes"), "*.png binary\n").unwrap();

        let checks = check_gitattributes_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not marked as binary"));
    }

    #[test]
    fn gitattributes_check_with_marker_passes() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();
        std::fs::write(
            dir.path().join(".gitattributes"),
            "# lpm\nlpm.lockb binary\n",
        )
        .unwrap();

        let checks = check_gitattributes_state(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert!(checks[0].detail.contains("marked as binary"));
    }

    // ── Fix execution tests ─────────────────────────────────────────────

    #[test]
    fn fix_binary_lockfile_regenerates_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let mut lf = lpm_lockfile::Lockfile::new();
        lf.add_package(lpm_lockfile::LockedPackage {
            name: "react".to_string(),
            version: "18.0.0".to_string(),
            source: Some("registry+https://registry.npmjs.org".to_string()),
            integrity: None,
            dependencies: vec![],
            alias_dependencies: vec![],
            peers: vec![],
            tarball: None,
        });
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        // No lpm.lockb exists yet
        assert!(!dir.path().join("lpm.lockb").exists());

        // Fix should create it
        fix_binary_lockfile(dir.path()).unwrap();
        assert!(dir.path().join("lpm.lockb").exists());

        // The regenerated binary should be valid and contain the same data
        let reader =
            lpm_lockfile::binary::BinaryLockfileReader::open(&dir.path().join("lpm.lockb"))
                .unwrap()
                .unwrap();
        assert_eq!(reader.package_count(), 1);
        let pkg = reader.find_package("react").unwrap();
        assert_eq!(pkg.version(), "18.0.0");
    }

    #[test]
    fn fix_binary_lockfile_overwrites_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let lf = lpm_lockfile::Lockfile::new();
        lf.write_to_file(&dir.path().join("lpm.lock")).unwrap();

        // Write corrupt binary
        std::fs::write(dir.path().join("lpm.lockb"), b"GARBAGE_DATA").unwrap();

        // Fix should overwrite with valid binary
        fix_binary_lockfile(dir.path()).unwrap();

        let reader =
            lpm_lockfile::binary::BinaryLockfileReader::open(&dir.path().join("lpm.lockb"))
                .unwrap()
                .unwrap();
        assert_eq!(reader.package_count(), 0);
    }

    #[test]
    fn fix_binary_lockfile_fails_without_toml() {
        let dir = tempfile::tempdir().unwrap();
        // No lpm.lock
        let result = fix_binary_lockfile(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn fix_gitattributes_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!dir.path().join(".gitattributes").exists());

        fix_gitattributes(dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
        assert!(content.contains("lpm.lockb binary"));
    }

    #[test]
    fn fix_gitattributes_appends_to_existing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".gitattributes"), "*.png binary\n").unwrap();

        fix_gitattributes(dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join(".gitattributes")).unwrap();
        assert!(content.contains("*.png binary"));
        assert!(content.contains("lpm.lockb binary"));
    }

    // ── Tunnel domain checks (format validation, no auth) ──────────

    #[tokio::test]
    async fn tunnel_check_skipped_without_lpm_json() {
        let dir = tempfile::tempdir().unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert!(checks.is_empty(), "no tunnel check when no lpm.json");
    }

    #[tokio::test]
    async fn tunnel_check_skipped_without_tunnel_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "runtime": { "node": "22" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert!(checks.is_empty(), "no tunnel check when no tunnel section");
    }

    #[tokio::test]
    async fn tunnel_check_warns_bare_domain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("not a full domain"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_unknown_base_domain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme.lpm.run" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(
            checks[0].detail.contains("unknown base domain"),
            "should reject unannounced lpm.run: {}",
            checks[0].detail
        );
    }

    #[tokio::test]
    async fn tunnel_check_passes_valid_domain_unauthenticated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme-api.lpm.llc" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert!(checks[0].detail.contains("configured"));
        assert!(checks[0].detail.contains("login to verify"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_short_subdomain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "ab.lpm.fyi" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("3-32 characters"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_uppercase_subdomain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "ACME.lpm.fyi" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(checks[0].detail.contains("lowercase"));
    }

    #[tokio::test]
    async fn tunnel_check_warns_leading_hyphen() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "-acme.lpm.fyi" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(
            checks[0]
                .detail
                .contains("must not start or end with a hyphen"),
            "should reject leading hyphen: {}",
            checks[0].detail
        );
    }

    #[tokio::test]
    async fn tunnel_check_warns_trailing_hyphen() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tunnel": { "domain": "acme-.lpm.llc" } }"#,
        )
        .unwrap();
        let client = RegistryClient::new();
        let checks = check_tunnel_domain(dir.path(), &client, false).await;
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Warn));
        assert!(
            checks[0]
                .detail
                .contains("must not start or end with a hyphen"),
            "should reject trailing hyphen: {}",
            checks[0].detail
        );
    }

    // ── validate_lpm_json tests ────────────────────────────────────────

    #[test]
    fn validate_lpm_json_no_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_lpm_json(dir.path()).is_none());
    }

    #[test]
    fn validate_lpm_json_empty_object_passes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "{}").unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "empty object should pass: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_invalid_json_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "{ not json").unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Fail));
        assert!(result.detail.contains("invalid JSON"));
    }

    #[test]
    fn validate_lpm_json_array_root_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), "[1, 2, 3]").unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Fail));
        assert!(result.detail.contains("must be a JSON object"));
    }

    #[test]
    fn validate_lpm_json_unknown_field_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "bogus_field": true }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("unknown field \"bogus_field\""));
    }

    #[test]
    fn validate_lpm_json_publish_field_accepted() {
        // Regression test for publish is a valid LpmJsonConfig field
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "publish": { "registries": ["lpm"] } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "publish should be accepted: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_https_field_accepted() {
        // Regression test for https is a valid LpmJsonConfig field
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "https": true }"#).unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "https should be accepted: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_vault_field_rejected() {
        // vault is NOT in LpmJsonConfig — should be flagged as unknown
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "vault": {} }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(
            matches!(result.severity, Severity::Warn),
            "vault should be unknown: {}",
            result.detail
        );
        assert!(result.detail.contains("unknown field \"vault\""));
    }

    #[test]
    fn validate_lpm_json_all_known_fields_pass() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{
                "runtime": { "node": ">=22" },
                "env": { "dev": ".env.development" },
                "tasks": { "build": { "command": "tsc" } },
                "tools": {},
                "services": { "web": { "command": "next dev" } },
                "tunnel": { "domain": "acme.lpm.fyi" },
                "publish": { "registries": ["lpm", "npm"] },
                "https": true
            }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path());
        let check = result.expect("should return a check");
        assert!(
            matches!(check.severity, Severity::Pass),
            "all known fields should pass: {}",
            check.detail
        );
    }

    #[test]
    fn validate_lpm_json_runtime_non_object_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "runtime": "node" }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_runtime_unsupported_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "runtime": { "deno": ">=2.0.0" } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("not yet supported"));
    }

    #[test]
    fn validate_lpm_json_tasks_string_value_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": "tsc" } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_task_unknown_field_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": { "command": "tsc", "bogus": true } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("unknown field \"bogus\""));
    }

    #[test]
    fn validate_lpm_json_task_cache_non_bool_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": { "command": "tsc", "cache": "yes" } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("cache must be a boolean"));
    }

    #[test]
    fn validate_lpm_json_task_outputs_non_array_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "build": { "command": "tsc", "outputs": "dist" } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("outputs must be an array"));
    }

    #[test]
    fn validate_lpm_json_task_depends_on_non_array_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "tasks": { "test": { "command": "vitest", "dependsOn": "build" } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("dependsOn must be an array"));
    }

    #[test]
    fn validate_lpm_json_tools_non_object_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "tools": "biome" }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_services_missing_command_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "services": { "api": { "port": 3000 } } }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("missing required \"command\""));
    }

    #[test]
    fn validate_lpm_json_services_non_object_warns() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lpm.json"), r#"{ "services": "web" }"#).unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(result.detail.contains("must be an object"));
    }

    #[test]
    fn validate_lpm_json_multiple_issues_counted() {
        let dir = tempfile::tempdir().unwrap();
        // 2 unknown fields + runtime non-object + serde schema error = 4 issues
        std::fs::write(
            dir.path().join("lpm.json"),
            r#"{ "bogus1": 1, "bogus2": 2, "runtime": "bad" }"#,
        )
        .unwrap();
        let result = validate_lpm_json(dir.path()).unwrap();
        assert!(matches!(result.severity, Severity::Warn));
        assert!(
            result.detail.contains("issues"),
            "should report multiple issues: {}",
            result.detail
        );
        // Verify it's more than 1 issue (the exact count depends on serde fallback too)
        assert!(
            result.detail.starts_with("4 issues") || result.detail.starts_with("3 issues"),
            "should have 3-4 issues: {}",
            result.detail
        );
    }

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

    /// L37: the shim-target verifier passes when every owned shim is a
    /// symlink pointing at the expected `<install-root>/node_modules/.bin/<bin>`.
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

    /// L37: a regular file at the shim path (the same-user PATH-hijack
    /// shape — attacker drops their own `bin-a` script at
    /// `~/.lpm/bin/bin-a` instead of leaving the lpm-emitted symlink)
    /// must surface as a warning, not pass.
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
            "L37: warn must name the regular-file vs symlink shape, got: {}",
            check.detail
        );
        assert!(check.detail.contains("PATH hijack"));
    }

    /// L37: a symlink whose target points at the wrong install root
    /// (stale rollback artifact, or attacker repointing the shim) must
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
            "L37: warn must name the actual target, got: {}",
            check.detail
        );
    }

    /// L38: a manifest with TOML-valid but structurally invalid rows
    /// (a `packages.*.root` that fails the
    /// `validated_install_root_relative` shape check) must fail with
    /// the new structural-invalid catalog entry, not pass.
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

    /// L38: a dangling alias row (alias pointing at a package that
    /// isn't in `packages`) must also fail the structural check.
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

    /// L39: trusted-deps absent → pass with "no host-global approvals"
    /// note. Other failure modes covered by additional tests below.
    #[test]
    fn check_global_trusted_deps_passes_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        let check = check_global_trusted_deps(&root);
        assert!(matches!(check.severity, Severity::Pass));
        assert!(check.detail.contains("not present"));
    }

    /// L39: trusted-deps malformed JSON → fail naming the schema-reset
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

    /// Audit: finding 2 (Medium): Check 17 must use the authoritative
    /// `validate_install_root` predicate. Pre-fix, it only checked
    /// `.lpm-install-ready` presence, so a half-corrupted install with
    /// a marker but missing bin targets would have been reported
    /// HEALTHY by doctor — then broken under the user's `lpm install -g`
    /// attempt.
    ///
    /// This test creates exactly that shape: marker written, then the
    /// bin target deleted. Post-fix Check 17 must report Fail because
    /// `validate_install_root` returns `MissingBinTarget`.
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
            "marker-present-but-bin-target-missing must Fail (pre-fix passed): {}",
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
            "post-audit Check 17 uses the authoritative predicate \
             and renders all sub-failures under the `not ready` category: {}",
            check.detail,
        );
        assert!(check.detail.contains("MissingMarker"));
    }

    // ── day-7 (F17): check_local_source_paths ───────────────────

    fn write_pkg_json(dir: &Path, content: &str) {
        std::fs::write(dir.join("package.json"), content).unwrap();
    }

    #[test]
    fn check_local_source_paths_returns_empty_for_no_local_deps() {
        // Project with only registry deps → empty Vec, doctor stays
        // quiet about the file:/link: feature surface.
        let dir = tempfile::tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"lodash":"^4.0.0"}}"#,
        );
        let checks = check_local_source_paths(dir.path());
        assert!(checks.is_empty());
    }

    #[test]
    fn check_local_source_paths_passes_valid_directory_dep() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("packages").join("local-thing");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(
            local.join("package.json"),
            br#"{"name":"local-thing","version":"1.0.0"}"#,
        )
        .unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"local-thing":"file:./packages/local-thing"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(checks[0].passed);
        assert!(matches!(checks[0].severity, Severity::Pass));
        assert!(checks[0].detail.contains("directory"));
    }

    #[test]
    fn check_local_source_paths_passes_valid_tarball_dep() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"fake tarball").unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"foo":"file:./foo.tgz"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(checks[0].passed);
        assert!(checks[0].detail.contains("tarball"));
    }

    #[test]
    fn check_local_source_paths_fails_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"missing":"file:./does-not-exist"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Fail));
        assert!(checks[0].detail.contains("unreadable"));
        assert!(checks[0].detail.contains("file:./does-not-exist"));
    }

    #[test]
    fn check_local_source_paths_fails_directory_without_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("packages").join("no-manifest");
        std::fs::create_dir_all(&local).unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"broken":"file:./packages/no-manifest"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Fail));
        assert!(checks[0].detail.contains("without package.json"));
    }

    #[test]
    fn check_local_source_paths_fails_link_pointing_at_regular_file() {
        // link: requires a directory; pointing at a tarball is a
        // user error caught at install time. Doctor surfaces it
        // pre-install with an actionable hint.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"fake").unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"bad":"link:./foo.tgz"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(matches!(checks[0].severity, Severity::Fail));
        assert!(checks[0].detail.contains("link:"));
        assert!(checks[0].detail.contains("regular file"));
    }

    #[test]
    fn check_local_source_paths_passes_valid_link_dep() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("shared").join("util");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(
            local.join("package.json"),
            br#"{"name":"util","version":"0.1.0"}"#,
        )
        .unwrap();
        write_pkg_json(
            dir.path(),
            r#"{"name":"app","dependencies":{"util":"link:./shared/util"}}"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 1);
        assert!(checks[0].passed);
    }

    #[test]
    fn check_local_source_paths_reports_multiple_deps_separately() {
        // A mix of pass + fail produces one Check entry per dep so
        // each is individually visible/actionable in doctor output.
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good");
        std::fs::create_dir_all(&good).unwrap();
        std::fs::write(
            good.join("package.json"),
            br#"{"name":"good","version":"1.0.0"}"#,
        )
        .unwrap();
        write_pkg_json(
            dir.path(),
            r#"{
                "name":"app",
                "dependencies":{
                    "good":"file:./good",
                    "missing":"file:./does-not-exist",
                    "lodash":"^4.0.0"
                }
            }"#,
        );

        let checks = check_local_source_paths(dir.path());
        // 2 file: deps → 2 Check entries; lodash registry → ignored.
        assert_eq!(checks.len(), 2);
        let pass_count = checks.iter().filter(|c| c.passed).count();
        let fail_count = checks
            .iter()
            .filter(|c| matches!(c.severity, Severity::Fail))
            .count();
        assert_eq!(pass_count, 1);
        assert_eq!(fail_count, 1);
    }

    #[test]
    fn check_local_source_paths_walks_all_dep_field_kinds() {
        // dependencies, devDependencies, peerDependencies,
        // optionalDependencies all walked. Each surfaces if it has
        // a file:/link: spec.
        let dir = tempfile::tempdir().unwrap();
        for name in ["a", "b", "c", "d"] {
            let pkg = dir.path().join(name);
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::write(
                pkg.join("package.json"),
                format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
            )
            .unwrap();
        }
        write_pkg_json(
            dir.path(),
            r#"{
                "name":"app",
                "dependencies":{"a":"file:./a"},
                "devDependencies":{"b":"file:./b"},
                "peerDependencies":{"c":"file:./c"},
                "optionalDependencies":{"d":"file:./d"}
            }"#,
        );

        let checks = check_local_source_paths(dir.path());
        assert_eq!(checks.len(), 4, "all dep field kinds must surface");
    }
}
