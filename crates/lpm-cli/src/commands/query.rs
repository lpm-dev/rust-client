//! `lpm query` — CSS-like dependency tree inspection.
//!
//! Queries installed packages using a selector syntax that targets
//! behavioral tags, state, and dependency relationships.
//!
//! ## Examples
//!
//! ```bash
//! lpm query ":eval"                   # All packages using eval
//! lpm query ":scripts:not(:built)"    # Unbuilt packages with scripts
//! lpm query ":root > :network"        # Direct deps that access network
//! lpm query ":eval:child-process"     # Packages with eval AND child_process
//! lpm query ":eval,:network"          # Packages with eval OR network
//! lpm query "#express"                # Package by exact name
//! lpm query --count                   # Tag counts grouped by severity
//! lpm query ":eval" --assert-none     # CI gate: exit 1 if any match
//! ```

use crate::commands::audit::inventory::PackageInventory;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use lpm_security::behavioral::PackageAnalysis;
use lpm_security::query::{
    self, DepGraph, DepGraphEntry, PackageContext, Severity, count_all_tags, matches_with_key,
    parse_selector,
};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Lifecycle script phases to check for `has_scripts`.
const LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

/// Build state marker filename (must match build.rs).
const BUILD_MARKER: &str = ".lpm-built";

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    selector_str: Option<&str>,
    count_mode: bool,
    json_output: bool,
    verbose: bool,
    assert_none: bool,
    format: &str,
) -> Result<(), LpmError> {
    let store_version = lpm_store::StoreVersion::from_env();
    let selector = if count_mode {
        None
    } else {
        let selector_str = selector_str.ok_or_else(|| {
            LpmError::Registry(
                "No selector provided. Usage: lpm query \":eval\" or lpm query --count".into(),
            )
        })?;
        Some(
            parse_selector(selector_str)
                .map_err(|e| LpmError::Registry(format!("Invalid selector: {e}")))?,
        )
    };
    // ── Pre-discovery (cheap, no store touch) ─────────────────────────
    //
    // Determine whether this is an LPM-managed project before paying
    // for the lock or the full inventory load. `discover` only reads
    // the project's lockfile — it never touches `~/.lpm/store/`.
    let mut pre_discovery = PackageInventory::discover(project_dir)?;
    if selector
        .as_ref()
        .is_some_and(|selector| selector.uses_workspace_root())
    {
        pre_discovery.include_workspace_root_graph();
    }
    let is_lpm_project =
        pre_discovery.manager == crate::commands::audit::discovery::ManagerKind::Lpm;

    // ── Load inventory + lifecycle/build-state under the right lock ───
    //
    // For LPM projects, inventory and disk-state loading read package bytes
    // from the store. Keep both operations under the shared store lock so
    // they cannot race store cleanup.
    //
    // For non-LPM projects, neither slice touches the store; no lock.
    //
    // Maps use owned `String` keys (not `&str`) because the inventory
    // is built inside the closure and moves out, which would invalidate
    // borrows into `inv.discovery.packages`.
    let mut has_scripts = Vec::new();
    let mut is_built = Vec::new();

    let inv: PackageInventory = if is_lpm_project {
        let lpm_root_outer = lpm_common::LpmRoot::from_env()?;
        let lock_path = lpm_root_outer.store_lock();
        let lpm_root_inner = lpm_root_outer;
        lpm_common::with_shared_lock(lock_path, || {
            let inv = PackageInventory::from_discovery_with_lpm_root(
                pre_discovery,
                store_version,
                Some(&lpm_root_inner),
            );
            populate_package_disk_state(
                &inv,
                Some(&lpm_root_inner),
                inv.baseline_index.as_ref(),
                &mut has_scripts,
                &mut is_built,
            );
            Ok(inv)
        })?
    } else {
        let inv =
            PackageInventory::from_discovery_with_lpm_root(pre_discovery, store_version, None);
        populate_package_disk_state(&inv, None, None, &mut has_scripts, &mut is_built);
        inv
    };

    if inv.discovery.packages.is_empty() {
        if json_output {
            println!("[]");
        } else {
            install_ui::warn("No packages found");
        }
        return Ok(());
    }

    // Read root package.json for direct dependencies
    let root_dep_names = read_root_dependencies(project_dir);

    let project_root = &inv.discovery.project_root;

    // Fetch vulnerability state
    let mut vulnerable_versions: HashMap<String, HashSet<String>> = HashMap::new();

    // @lpm.dev: check registry metadata
    let lpm_names: Vec<String> = inv
        .discovery
        .packages
        .iter()
        .filter(|p| p.name.starts_with("@lpm.dev/"))
        .map(|p| p.name.clone())
        .collect();

    if !lpm_names.is_empty()
        && let Ok(metadata_map) = client.batch_metadata(&lpm_names).await
    {
        for pkg in &inv.discovery.packages {
            if !pkg.name.starts_with("@lpm.dev/") {
                continue;
            }
            if let Some(metadata) = metadata_map.get(&pkg.name)
                && let Some(vm) = metadata.version(&pkg.version).or_else(|| metadata.latest())
                && vm.vulnerabilities.as_ref().is_some_and(|v| !v.is_empty())
            {
                vulnerable_versions
                    .entry(pkg.name.clone())
                    .or_default()
                    .insert(pkg.version.clone());
            }
        }
    }

    // OSV for all packages
    for (name, versions) in query_osv_vulnerable_by_nv(&inv.npm_package_pairs()).await {
        vulnerable_versions
            .entry(name)
            .or_default()
            .extend(versions);
    }

    // ── Workspace detection ───────────────────────────────────────────
    //
    // If the lockfile root (project_root) differs from the invocation dir
    // (project_dir), we're in a monorepo sub-workspace. In that case:
    // - :root deps = invocation dir's package.json dependencies
    // - :workspace-root deps = lockfile root's package.json dependencies
    let workspace_project_root = inv
        .discovery
        .workspace_root
        .as_ref()
        .map(|workspace| workspace.project_root.as_path())
        .or_else(|| (project_root != project_dir).then_some(project_root.as_path()));
    let is_workspace = workspace_project_root.is_some();
    let workspace_root_dep_names = if let Some(workspace_root) = workspace_project_root {
        read_root_dependencies(workspace_root)
    } else {
        HashSet::new()
    };
    let workspace_root_instances: HashSet<_> = inv
        .discovery
        .workspace_root
        .as_ref()
        .into_iter()
        .flat_map(|workspace| workspace.lockfile.root_resolutions.values())
        .filter_map(|resolution| resolution.instance_id)
        .collect();

    if count_mode {
        let contexts = inv
            .discovery
            .packages
            .iter()
            .enumerate()
            .map(|(index, package)| PackageContext {
                name: &package.name,
                version: &package.version,
                path: &package.path,
                analysis: inv.analyses[index].as_deref(),
                has_scripts: has_scripts.get(index).copied().unwrap_or(false),
                is_built: is_built.get(index).copied().unwrap_or(false),
                is_vulnerable: vulnerable_versions
                    .get(&package.name)
                    .is_some_and(|versions| versions.contains(&package.version)),
                is_deprecated: false,
                is_root: false,
                is_workspace_root_dep: false,
            })
            .collect::<Vec<_>>();
        run_count_mode(&contexts, json_output);
        return Ok(());
    }

    let selector_str = selector_str.expect("selector mode validates the selector before discovery");
    let selector = selector
        .as_ref()
        .expect("selector mode parses the selector before discovery");
    let needs_dependency_graph = selector.needs_dependency_graph() || format == "mermaid";

    // ── Build PackageContexts ───────────────────────────────────────────

    let owned_graph_keys: Vec<String> = if is_lpm_project && needs_dependency_graph {
        inv.discovery
            .packages
            .iter()
            .map(|package| package.analysis_key())
            .collect()
    } else {
        Vec::new()
    };
    let graph_keys: Vec<&str> = if is_lpm_project && needs_dependency_graph {
        owned_graph_keys.iter().map(String::as_str).collect()
    } else {
        inv.discovery
            .packages
            .iter()
            .map(|package| package.path.as_str())
            .collect()
    };
    let display_paths: Vec<Cow<'_, str>> = inv
        .discovery
        .packages
        .iter()
        .zip(&inv.source_paths)
        .map(|(package, source_path)| {
            source_path.as_deref().map_or_else(
                || Cow::Borrowed(package.path.as_str()),
                Path::to_string_lossy,
            )
        })
        .collect();
    let pkg_contexts: Vec<PackageContext<'_>> = inv
        .discovery
        .packages
        .iter()
        .enumerate()
        .map(|(index, pkg)| PackageContext {
            name: &pkg.name,
            version: &pkg.version,
            path: display_paths[index].as_ref(),
            analysis: inv.analyses[index].as_deref(),
            has_scripts: has_scripts.get(index).copied().unwrap_or(false),
            is_built: is_built.get(index).copied().unwrap_or(false),
            is_vulnerable: vulnerable_versions
                .get(&pkg.name)
                .is_some_and(|versions| versions.contains(&pkg.version)),
            is_deprecated: false,
            is_root: false,
            is_workspace_root_dep: pkg.instance_id.map_or_else(
                || is_workspace && workspace_root_dep_names.contains(&pkg.name),
                |instance_id| workspace_root_instances.contains(&instance_id),
            ),
        })
        .collect();

    // Selector mode — filter packages by selector
    // ── Build dependency graph ──────────────────────────────────────────

    // For LPM projects with a lockfile, use name-based graph
    let lockfile = is_lpm_project
        .then(|| inv.discovery.retained_lpm_lockfile())
        .flatten();

    let dep_graph_entries: Vec<DepGraphEntry<'_>>;
    let mut dep_graph = if !needs_dependency_graph {
        DepGraph::empty()
    } else if let Some(lf) = lockfile {
        DepGraph::from_lpm_instances(&lf.packages, &graph_keys, &lf.root_resolutions)
    } else {
        dep_graph_entries = inv
            .discovery
            .packages
            .iter()
            .map(|pkg| DepGraphEntry {
                name: &pkg.name,
                version: &pkg.version,
                path: &pkg.path,
                dependencies: &pkg.dependencies,
            })
            .collect();
        DepGraph::from_instances(&dep_graph_entries, &root_dep_names)
    };

    // Populate workspace root deps for :workspace-root combinator
    if needs_dependency_graph
        && is_workspace
        && (!workspace_root_dep_names.is_empty() || !workspace_root_instances.is_empty())
    {
        let ws_deps: HashSet<&str> = match dep_graph.key_mode {
            query::GraphKeyMode::Name => {
                // Name-keyed: workspace root deps are just the names
                workspace_root_dep_names
                    .iter()
                    .map(|s| s.as_str())
                    .collect()
            }
            query::GraphKeyMode::Path => {
                // Path-keyed: resolve names to top-level node_modules paths
                inv.discovery
                    .packages
                    .iter()
                    .filter(|p| {
                        workspace_root_dep_names.contains(&p.name)
                            && p.path == format!("node_modules/{}", p.name)
                    })
                    .map(|p| p.path.as_str())
                    .collect()
            }
            query::GraphKeyMode::Instance => inv
                .discovery
                .packages
                .iter()
                .zip(graph_keys.iter().copied())
                .filter(|(package, _)| {
                    package.instance_id.map_or_else(
                        || workspace_root_dep_names.contains(&package.name),
                        |instance_id| workspace_root_instances.contains(&instance_id),
                    )
                })
                .map(|(_, key)| key)
                .collect(),
        };
        dep_graph.set_workspace_root_deps(ws_deps);
    }

    // Build all_packages map for combinator matching
    let all_packages: HashMap<&str, PackageContext<'_>> = if needs_dependency_graph {
        graph_keys
            .iter()
            .copied()
            .zip(pkg_contexts.iter())
            .map(|(key, p)| {
                (
                    key,
                    PackageContext {
                        name: p.name,
                        version: p.version,
                        path: p.path,
                        analysis: p.analysis,
                        has_scripts: p.has_scripts,
                        is_built: p.is_built,
                        is_vulnerable: p.is_vulnerable,
                        is_deprecated: p.is_deprecated,
                        is_root: p.is_root,
                        is_workspace_root_dep: p.is_workspace_root_dep,
                    },
                )
            })
            .collect()
    } else {
        HashMap::new()
    };

    // Match packages
    let matched: Vec<(usize, &PackageContext<'_>)> = pkg_contexts
        .iter()
        .enumerate()
        .zip(graph_keys.iter().copied())
        .filter_map(|((index, pkg), graph_key)| {
            matches_with_key(selector, pkg, graph_key, &dep_graph, &all_packages)
                .then_some((index, pkg))
        })
        .collect();

    // Output — Mermaid format
    if format == "mermaid" {
        if let Some(lf) = lockfile {
            let matched_indices = matched.iter().map(|(index, _)| *index).collect::<Vec<_>>();
            output_mermaid(&matched_indices, &lf.packages, selector_str);
            return Ok(());
        }
        // For npm projects, Mermaid output is not yet supported
        // (would need to build edges from DiscoveredPackage deps)
        return Err(LpmError::Registry(
            "Mermaid output is only supported for LPM-managed projects.".into(),
        ));
    }

    // Output — list (default) or JSON
    if json_output {
        let json_results: Vec<serde_json::Value> = matched
            .iter()
            .map(|(index, pkg)| {
                let mut obj = serde_json::json!({
                    "name": pkg.name,
                    "version": pkg.version,
                });
                if let Some(instance_id) = inv.discovery.packages[*index].instance_id {
                    obj["instanceId"] = serde_json::json!(instance_id.to_string());
                }
                if !pkg.path.is_empty() {
                    obj["path"] = serde_json::json!(pkg.path);
                }
                if verbose {
                    if let Some(analysis) = pkg.analysis {
                        obj["analysis"] = serde_json::to_value(analysis).unwrap_or_default();
                    }
                    obj["hasScripts"] = serde_json::json!(pkg.has_scripts);
                    obj["isBuilt"] = serde_json::json!(pkg.is_built);
                    obj["isVulnerable"] = serde_json::json!(pkg.is_vulnerable);
                }
                obj
            })
            .collect();

        println!(
            "{}",
            serde_json::to_string_pretty(&json_results).unwrap_or_else(|_| "[]".into())
        );
    } else if matched.is_empty() {
        install_ui::warn_untrusted(&format!("No packages match {selector_str}"));
    } else {
        for (_, pkg) in &matched {
            let mut state_labels = Vec::new();

            if pkg.has_scripts {
                state_labels.push("scripts".to_string());
            }
            if pkg.is_built {
                state_labels.push("built".to_string());
            }

            let state_str = if state_labels.is_empty() {
                install_ui::field("")
            } else {
                install_ui::dim(&format!(" ({})", state_labels.join(", ")))
            };

            // Show path when it differs from the default (indicates a nested instance)
            let path_suffix =
                if !pkg.path.is_empty() && pkg.path != format!("node_modules/{}", pkg.name) {
                    install_ui::dim(&format!(" {}", pkg.path))
                } else {
                    install_ui::field("")
                };
            println!(
                "{}",
                crate::install_ui::terminal_line!(
                    "    {}@{}{}{}",
                    &pkg.name,
                    &pkg.version,
                    state_str,
                    path_suffix
                )
            );

            let tags = pkg.analysis.map(collect_active_tags).unwrap_or_default();
            if !tags.is_empty() {
                println!(
                    "      {} {}",
                    install_ui::dim("tags:"),
                    install_ui::dim(&tags.join(", "))
                );
            }
        }
        println!();
        install_ui::warn_untrusted(&format!(
            "{} {} matched {selector_str}",
            matched.len(),
            if matched.len() == 1 {
                "package"
            } else {
                "packages"
            }
        ));
    }

    // --assert-none: exit 1 if ANY packages matched (CI gate)
    if assert_none && !matched.is_empty() {
        return Err(LpmError::Registry(format!(
            "assertion failed: {} package{} matched selector '{selector_str}'",
            matched.len(),
            if matched.len() == 1 { "" } else { "s" }
        )));
    }

    Ok(())
}

/// Count mode: show tag counts for all packages, grouped by severity tier.
fn run_count_mode(packages: &[PackageContext<'_>], json_output: bool) {
    let counts = count_all_tags(packages);

    if json_output {
        let mut json_obj = serde_json::Map::new();
        for tc in &counts {
            json_obj.insert(
                tc.pseudo_class
                    .display_name()
                    .trim_start_matches(':')
                    .to_string(),
                serde_json::json!(tc.count),
            );
        }
        json_obj.insert("total".to_string(), serde_json::json!(packages.len()));
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(json_obj))
                .unwrap_or_else(|_| "{}".into())
        );
        return;
    }

    println!(
        "  {} across {} packages\n",
        "Tag counts".bold(),
        packages.len().to_string().bold()
    );

    // Group by severity
    #[allow(clippy::type_complexity)]
    let tiers: [(Severity, &str, fn(&str) -> String); 4] = [
        (Severity::Critical, "Critical", |s: &str| s.red().bold()),
        (Severity::High, "High", |s: &str| s.yellow().bold()),
        (Severity::Medium, "Medium", |s: &str| s.cyan().bold()),
        (Severity::Info, "Info", |s: &str| s.dimmed()),
    ];

    for (severity, label, colorize) in &tiers {
        let tier_counts: Vec<_> = counts
            .iter()
            .filter(|tc| tc.pseudo_class.severity() == *severity)
            .collect();

        if tier_counts.is_empty() {
            continue;
        }

        println!("  · {}", colorize(label));

        // Find max label length for alignment
        let max_label_len = tier_counts
            .iter()
            .map(|tc| tc.pseudo_class.display_name().len())
            .max()
            .unwrap_or(0);

        for tc in &tier_counts {
            let display = tc.pseudo_class.display_name();
            let padding = max_label_len - display.len();
            let count_str = if tc.count > 0 {
                tc.count.to_string().bold().to_string()
            } else {
                "0".dimmed().to_string()
            };
            println!("    {}{:padding$}  {count_str}", display.dimmed(), "",);
        }
        println!();
    }
}

/// Collect active tag names from a package analysis (for verbose output).
fn collect_active_tags(analysis: &PackageAnalysis) -> Vec<String> {
    let mut tags = Vec::new();

    // Source tags
    if analysis.source.eval {
        tags.push("eval".into());
    }
    if analysis.source.network {
        tags.push("network".into());
    }
    if analysis.source.filesystem {
        tags.push("fs".into());
    }
    if analysis.source.shell {
        tags.push("shell".into());
    }
    if analysis.source.child_process {
        tags.push("child-process".into());
    }
    if analysis.source.native_bindings {
        tags.push("native".into());
    }
    if analysis.source.crypto {
        tags.push("crypto".into());
    }
    if analysis.source.dynamic_require {
        tags.push("dynamic-require".into());
    }
    if analysis.source.environment_vars {
        tags.push("env".into());
    }
    if analysis.source.web_socket {
        tags.push("ws".into());
    }

    // Supply chain tags
    if analysis.supply_chain.obfuscated {
        tags.push("obfuscated".into());
    }
    if analysis.supply_chain.possible_obfuscation {
        tags.push("possible-obfuscation".into());
    }
    if analysis.supply_chain.high_entropy_strings {
        tags.push("high-entropy".into());
    }
    if analysis.supply_chain.minified {
        tags.push("minified".into());
    }
    if analysis.supply_chain.telemetry {
        tags.push("telemetry".into());
    }
    if analysis.supply_chain.url_strings {
        tags.push("url-strings".into());
    }
    if analysis.supply_chain.trivial {
        tags.push("trivial".into());
    }
    if analysis.supply_chain.protestware {
        tags.push("protestware".into());
    }

    // Manifest tags
    if analysis.manifest.git_dependency {
        tags.push("git-dep".into());
    }
    if analysis.manifest.http_dependency {
        tags.push("http-dep".into());
    }
    if analysis.manifest.wildcard_dependency {
        tags.push("wildcard-dep".into());
    }
    if analysis.manifest.copyleft_license {
        tags.push("copyleft".into());
    }
    if analysis.manifest.no_license {
        tags.push("no-license".into());
    }

    tags
}

/// Read direct dependencies from the root package.json.
fn read_root_dependencies(project_dir: &Path) -> HashSet<String> {
    let pkg_json_path = project_dir.join("package.json");
    let content = match lpm_common::read_text_file_capped(
        &pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(c) => c,
        Err(_) => return HashSet::new(),
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return HashSet::new(),
    };

    let mut deps = HashSet::new();

    if let Some(d) = parsed.get("dependencies").and_then(|d| d.as_object()) {
        for key in d.keys() {
            deps.insert(key.clone());
        }
    }
    if let Some(d) = parsed.get("devDependencies").and_then(|d| d.as_object()) {
        for key in d.keys() {
            deps.insert(key.clone());
        }
    }

    deps
}

fn populate_package_disk_state(
    inventory: &PackageInventory,
    lpm_root: Option<&lpm_common::LpmRoot>,
    baseline_index: Option<&crate::commands::audit::inventory::ProjectV2BaselineIndex>,
    has_scripts: &mut Vec<bool>,
    is_built: &mut Vec<bool>,
) {
    has_scripts.clear();
    has_scripts.resize(inventory.discovery.packages.len(), false);
    is_built.clear();
    is_built.resize(inventory.discovery.packages.len(), false);
    let project_root =
        crate::commands::audit::inventory::open_project_root(&inventory.discovery.project_root)
            .ok();
    for (index, package) in inventory.discovery.packages.iter().enumerate() {
        let Ok(directory) = crate::commands::audit::inventory::open_package_source_directory(
            project_root.as_ref(),
            package,
            lpm_root,
            baseline_index,
        ) else {
            continue;
        };
        has_scripts[index] = check_has_lifecycle_scripts(&directory);
        is_built[index] = has_regular_build_marker(&directory);
    }
}

fn check_has_lifecycle_scripts(package_dir: &cap_std::fs::Dir) -> bool {
    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};

    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = match package_dir.open_with("package.json", &options) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let metadata = match file.metadata() {
        Ok(metadata) if metadata.is_file() && !metadata.is_symlink() => metadata,
        _ => return false,
    };
    let content = match lpm_common::read_text_file_capped_from_open_file_with_known_size(
        file.into_std(),
        Path::new("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
        metadata.len(),
    ) {
        Ok(content) => content,
        Err(_) => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let scripts = match parsed.get("scripts").and_then(|s| s.as_object()) {
        Some(s) => s,
        None => return false,
    };

    LIFECYCLE_SCRIPTS
        .iter()
        .any(|phase| scripts.contains_key(*phase))
}

fn has_regular_build_marker(package_dir: &cap_std::fs::Dir) -> bool {
    package_dir
        .symlink_metadata(BUILD_MARKER)
        .is_ok_and(|metadata| metadata.is_file() && !metadata.is_symlink())
}

/// Output matching packages as a Mermaid dependency subgraph.
fn output_mermaid(
    matched_indices: &[usize],
    all_packages: &[lpm_lockfile::LockedPackage],
    selector_str: &str,
) {
    let key_by_instance: HashMap<_, _> = all_packages
        .iter()
        .enumerate()
        .filter_map(|(index, package)| package.instance_id.map(|id| (id, index)))
        .collect();
    let mut keys_by_coords: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (index, package) in all_packages.iter().enumerate() {
        keys_by_coords
            .entry((&package.name, &package.version))
            .or_default()
            .push(index);
    }
    let matched: HashSet<usize> = matched_indices.iter().copied().collect();
    let mut nodes = matched.clone();
    let mut edges = HashSet::new();
    for (index, package) in all_packages.iter().enumerate() {
        let exact_targets = package
            .dependency_targets
            .values()
            .chain(package.peer_targets.values())
            .filter_map(|instance_id| key_by_instance.get(instance_id).copied())
            .collect::<Vec<_>>();
        let targets = if exact_targets.is_empty() {
            package
                .dependencies
                .iter()
                .filter_map(|dependency| {
                    let at = dependency.rfind('@')?;
                    keys_by_coords
                        .get(&(&dependency[..at], &dependency[at + 1..]))
                        .and_then(|indices| indices.first().copied())
                })
                .collect::<Vec<_>>()
        } else {
            exact_targets
        };
        for target in targets {
            if matched.contains(&index) || matched.contains(&target) {
                nodes.insert(index);
                nodes.insert(target);
                edges.insert((index, target));
            }
        }
    }
    let mut nodes = nodes.into_iter().collect::<Vec<_>>();
    nodes.sort_unstable();
    let mut edges = edges.into_iter().collect::<Vec<_>>();
    edges.sort_unstable();

    println!("graph TD");
    println!("    %% lpm query \"{}\"", selector_str);
    for index in nodes {
        let package = &all_packages[index];
        let instance_suffix = package
            .instance_id
            .map(|instance_id| format!("\\n{}", &instance_id.to_string()[..12]))
            .unwrap_or_default();
        println!(
            "    n{index}[\"{}@{}{}\"]",
            package.name, package.version, instance_suffix
        );
    }
    for (from, to) in edges {
        println!("    n{from} --> n{to}");
    }
    if !matched_indices.is_empty() {
        let ids = matched_indices
            .iter()
            .map(|index| format!("n{index}"))
            .collect::<Vec<_>>();
        println!("    style {} fill:#f96,stroke:#333", ids.join(","));
    }
}

/// Query OSV.dev for vulnerabilities given `(name, version)` pairs.
///
/// Works with any project type (LPM, npm, pnpm, yarn, bun).
/// Returns the set of package names that have at least one advisory.
/// Deduplicates queries by (name, version). Gracefully returns empty
/// set on network/parse failure.
async fn query_osv_vulnerable_by_nv(
    packages: &[(String, String)],
) -> HashMap<String, HashSet<String>> {
    if packages.is_empty() {
        return HashMap::new();
    }

    // Dedup by (name, version) — same artifact = one query
    let mut seen = HashSet::new();
    let mut deduped: Vec<&(String, String)> = Vec::new();
    for pair in packages {
        if seen.insert((&pair.0, &pair.1)) {
            deduped.push(pair);
        }
    }

    let Ok(client) = lpm_http::client_builder().build() else {
        return HashMap::new();
    };

    let queries: Vec<serde_json::Value> = deduped
        .iter()
        .map(|(name, version)| {
            serde_json::json!({
                "package": { "name": name, "ecosystem": "npm" },
                "version": version,
            })
        })
        .collect();

    let body = serde_json::json!({ "queries": queries });

    let response = match client
        .post("https://api.osv.dev/v1/querybatch")
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        _ => return HashMap::new(),
    };

    #[derive(serde::Deserialize)]
    struct OsvBatchResponse {
        results: Vec<OsvQueryResult>,
    }
    #[derive(serde::Deserialize)]
    struct OsvQueryResult {
        #[serde(default)]
        vulns: Vec<serde_json::Value>,
    }

    let result: OsvBatchResponse = match response.json().await {
        Ok(r) => r,
        Err(_) => return HashMap::new(),
    };

    let mut vulnerable: HashMap<String, HashSet<String>> = HashMap::new();
    for (i, query_result) in result.results.into_iter().enumerate() {
        if i >= deduped.len() {
            break;
        }
        if !query_result.vulns.is_empty() {
            vulnerable
                .entry(deduped[i].0.clone())
                .or_default()
                .insert(deduped[i].1.clone());
        }
    }

    vulnerable
}

#[cfg(test)]
mod tests {
    use super::*;
    use lpm_security::behavioral::manifest::ManifestTags;
    use lpm_security::behavioral::source::SourceTags;
    use lpm_security::behavioral::supply_chain::SupplyChainTags;
    use lpm_security::behavioral::{AnalysisMeta, PackageAnalysis};

    fn make_analysis(source: SourceTags) -> PackageAnalysis {
        PackageAnalysis {
            version: lpm_security::behavioral::SCHEMA_VERSION,
            analyzed_at: "T00:00:00Z".into(),
            source,
            supply_chain: SupplyChainTags::default(),
            manifest: ManifestTags::default(),
            meta: AnalysisMeta::default(),
        }
    }

    #[test]
    fn collect_active_tags_from_eval_network() {
        let analysis = make_analysis(SourceTags {
            eval: true,
            network: true,
            ..Default::default()
        });
        let tags = collect_active_tags(&analysis);
        assert!(tags.contains(&"eval".to_string()));
        assert!(tags.contains(&"network".to_string()));
        assert!(!tags.contains(&"shell".to_string()));
    }

    #[test]
    fn collect_active_tags_empty_analysis() {
        let analysis = make_analysis(SourceTags::default());
        let tags = collect_active_tags(&analysis);
        assert!(tags.is_empty());
    }

    #[test]
    fn collect_active_tags_all_source_tags() {
        let analysis = make_analysis(SourceTags {
            eval: true,
            network: true,
            filesystem: true,
            shell: true,
            child_process: true,
            native_bindings: true,
            crypto: true,
            dynamic_require: true,
            environment_vars: true,
            web_socket: true,
        });
        let tags = collect_active_tags(&analysis);
        assert_eq!(tags.len(), 10);
    }

    #[test]
    fn read_root_deps_from_package_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"react":"^18.0.0","lodash":"^4.17.0"},"devDependencies":{"jest":"^29.0.0"}}"#,
        )
        .unwrap();

        let deps = read_root_dependencies(dir.path());
        assert!(deps.contains("react"));
        assert!(deps.contains("lodash"));
        assert!(deps.contains("jest"));
        assert_eq!(deps.len(), 3);
    }

    #[test]
    fn read_root_deps_missing_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let deps = read_root_dependencies(dir.path());
        assert!(deps.is_empty());
    }

    #[test]
    fn check_lifecycle_scripts_detects_postinstall() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"postinstall":"node setup.js","test":"jest"}}"#,
        )
        .unwrap();

        let package_dir =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();
        assert!(check_has_lifecycle_scripts(&package_dir));
    }

    #[test]
    fn check_lifecycle_scripts_no_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"test":"jest","start":"node ."}}"#,
        )
        .unwrap();

        let package_dir =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();
        assert!(!check_has_lifecycle_scripts(&package_dir));
    }

    #[test]
    fn check_lifecycle_scripts_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let package_dir =
            cap_std::fs::Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();
        assert!(!check_has_lifecycle_scripts(&package_dir));
    }
}
