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
    self, DepGraph, DepGraphEntry, PackageContext, PseudoClass, Selector, Severity, count_all_tags,
    matches_with_key, parse_selector,
};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

/// Lifecycle script phases to check for `has_scripts`.
const LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall", "prepare"];

/// Build state marker filename (must match build.rs).
const BUILD_MARKER: &str = ".lpm-built";

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum QueryFormat {
    List,
    Mermaid,
}

impl fmt::Display for QueryFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::List => "list",
            Self::Mermaid => "mermaid",
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct QueryDataRequirements {
    scripts: bool,
    built: bool,
    vulnerabilities: bool,
    deprecations: bool,
}

impl QueryDataRequirements {
    fn for_request(
        selector: Option<&Selector>,
        count_mode: bool,
        json_output: bool,
        verbose: bool,
        format: QueryFormat,
    ) -> Self {
        let human_list = !count_mode && !json_output && format == QueryFormat::List;
        let verbose_json = !count_mode && json_output && verbose && format == QueryFormat::List;
        Self {
            scripts: count_mode
                || human_list
                || verbose_json
                || selector.is_some_and(selector_needs_scripts),
            built: human_list
                || verbose_json
                || selector.is_some_and(|selector| {
                    selector_uses_pseudo_class(selector, |class| class == PseudoClass::Built)
                }),
            vulnerabilities: count_mode
                || verbose_json
                || selector.is_some_and(selector_needs_vulnerabilities),
            deprecations: selector.is_some_and(|selector| {
                selector_uses_pseudo_class(selector, |class| class == PseudoClass::Deprecated)
            }),
        }
    }

    fn needs_disk_state(self) -> bool {
        self.scripts || self.built
    }
}

fn selector_needs_scripts(selector: &Selector) -> bool {
    selector_uses_pseudo_class(selector, |class| {
        matches!(class, PseudoClass::Scripts | PseudoClass::High)
    })
}

fn selector_needs_vulnerabilities(selector: &Selector) -> bool {
    selector_uses_pseudo_class(selector, |class| {
        matches!(class, PseudoClass::Vulnerable | PseudoClass::High)
    })
}

fn selector_uses_pseudo_class(
    selector: &Selector,
    predicate: impl Copy + Fn(PseudoClass) -> bool,
) -> bool {
    match selector {
        Selector::PseudoClass(class) => predicate(*class),
        Selector::And(parts) | Selector::Or(parts) => parts
            .iter()
            .any(|part| selector_uses_pseudo_class(part, predicate)),
        Selector::Not(inner) => selector_uses_pseudo_class(inner, predicate),
        Selector::DirectChild { parent, child } => {
            selector_uses_pseudo_class(parent, predicate)
                || selector_uses_pseudo_class(child, predicate)
        }
        Selector::Id(_) => false,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    selector_str: Option<&str>,
    count_mode: bool,
    json_output: bool,
    verbose: bool,
    assert_none: bool,
    format: QueryFormat,
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
    let requirements = QueryDataRequirements::for_request(
        selector.as_ref(),
        count_mode,
        json_output,
        verbose,
        format,
    );
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
            if requirements.needs_disk_state() {
                populate_package_disk_state(
                    &inv,
                    Some(&lpm_root_inner),
                    inv.baseline_index.as_ref(),
                    requirements.scripts,
                    requirements.built,
                    &mut has_scripts,
                    &mut is_built,
                );
            }
            Ok(inv)
        })?
    } else {
        let inv =
            PackageInventory::from_discovery_with_lpm_root(pre_discovery, store_version, None);
        if requirements.needs_disk_state() {
            populate_package_disk_state(
                &inv,
                None,
                None,
                requirements.scripts,
                requirements.built,
                &mut has_scripts,
                &mut is_built,
            );
        }
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

    let external_state = if requirements.vulnerabilities || requirements.deprecations {
        let package_pairs = inv
            .discovery
            .packages
            .iter()
            .map(|package| (package.name.clone(), package.version.clone()))
            .collect::<Vec<_>>();
        load_external_package_state(client, &package_pairs, requirements).await?
    } else {
        ExternalPackageState::default()
    };
    let vulnerable_versions = external_state.vulnerable_versions;
    let deprecated_versions = external_state.deprecated_versions;

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
                is_deprecated: deprecated_versions
                    .get(&package.name)
                    .is_some_and(|versions| versions.contains(&package.version)),
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
    let needs_dependency_graph =
        selector.needs_dependency_graph() || format == QueryFormat::Mermaid;

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
            is_deprecated: deprecated_versions
                .get(&pkg.name)
                .is_some_and(|versions| versions.contains(&pkg.version)),
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
    if format == QueryFormat::Mermaid {
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

#[derive(Default)]
struct ExternalPackageState {
    vulnerable_versions: HashMap<String, HashSet<String>>,
    deprecated_versions: HashMap<String, HashSet<String>>,
}

async fn load_external_package_state(
    client: &RegistryClient,
    packages: &[(String, String)],
    requirements: QueryDataRequirements,
) -> Result<ExternalPackageState, LpmError> {
    if !requirements.vulnerabilities && !requirements.deprecations {
        return Ok(ExternalPackageState::default());
    }

    let mut registry_seen = HashSet::with_capacity(packages.len());
    let mut registry_pairs = Vec::with_capacity(packages.len());
    let mut osv_seen = HashSet::with_capacity(packages.len());
    let mut osv_pairs = Vec::with_capacity(packages.len());
    for (name, version) in packages {
        let is_lpm_package = name.starts_with("@lpm.dev/");
        if (requirements.deprecations || requirements.vulnerabilities && is_lpm_package)
            && registry_seen.insert((name.as_str(), version.as_str()))
        {
            registry_pairs.push((name.clone(), version.clone()));
        }
        if requirements.vulnerabilities
            && !is_lpm_package
            && osv_seen.insert((name.as_str(), version.as_str()))
        {
            osv_pairs.push((name.clone(), version.clone()));
        }
    }

    let registry_future = load_registry_package_state(client, &registry_pairs, requirements);
    let osv_future = async {
        if osv_pairs.is_empty() {
            Ok(HashMap::new())
        } else {
            crate::commands::audit::query_vulnerable_versions(&osv_pairs).await
        }
    };
    let (mut state, osv_vulnerable_versions) = tokio::try_join!(registry_future, osv_future)?;
    for (name, versions) in osv_vulnerable_versions {
        state
            .vulnerable_versions
            .entry(name)
            .or_default()
            .extend(versions);
    }
    Ok(state)
}

async fn load_registry_package_state(
    client: &RegistryClient,
    packages: &[(String, String)],
    requirements: QueryDataRequirements,
) -> Result<ExternalPackageState, LpmError> {
    if packages.is_empty() {
        return Ok(ExternalPackageState::default());
    }

    let mut seen_names = HashSet::with_capacity(packages.len());
    let mut names = Vec::with_capacity(packages.len());
    for (name, _) in packages {
        if seen_names.insert(name.as_str()) {
            names.push(name.clone());
        }
    }
    let metadata = client
        .batch_metadata_deep_with_release_age_packages_and_package_specs(
            &names,
            &[],
            false,
            packages,
            None,
        )
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "registry metadata required by query could not be loaded: {error}"
            ))
        })?;

    let mut state = ExternalPackageState::default();
    for (name, version) in packages {
        let package_metadata = metadata.get(name).ok_or_else(|| {
            LpmError::Network(format!(
                "registry metadata response omitted package {name}; query results would be incomplete"
            ))
        })?;
        let version_metadata = package_metadata.version(version).ok_or_else(|| {
            LpmError::Network(format!(
                "registry metadata for {name} does not include installed version {version}; query results would be incomplete"
            ))
        })?;
        if requirements.vulnerabilities
            && name.starts_with("@lpm.dev/")
            && version_metadata
                .vulnerabilities
                .as_ref()
                .is_some_and(|vulnerabilities| !vulnerabilities.is_empty())
        {
            state
                .vulnerable_versions
                .entry(name.clone())
                .or_default()
                .insert(version.clone());
        }
        if requirements.deprecations
            && registry_deprecation_is_active(version_metadata.deprecated.as_ref())
        {
            state
                .deprecated_versions
                .entry(name.clone())
                .or_default()
                .insert(version.clone());
        }
    }
    Ok(state)
}

fn registry_deprecation_is_active(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::String(message)) => !message.trim().is_empty(),
        Some(value) => !value.is_null(),
        None => false,
    }
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
    load_scripts: bool,
    load_built: bool,
    has_scripts: &mut Vec<bool>,
    is_built: &mut Vec<bool>,
) {
    has_scripts.clear();
    is_built.clear();
    if load_scripts {
        has_scripts.resize(inventory.discovery.packages.len(), false);
    }
    if load_built {
        is_built.resize(inventory.discovery.packages.len(), false);
    }
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
        if load_scripts {
            has_scripts[index] = check_has_lifecycle_scripts(&directory);
        }
        if load_built {
            is_built[index] = has_regular_build_marker(&directory);
        }
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
    fn name_only_json_query_needs_no_external_or_disk_state() {
        let selector = parse_selector("#plain-pkg").unwrap();

        let requirements = QueryDataRequirements::for_request(
            Some(&selector),
            false,
            true,
            false,
            QueryFormat::List,
        );

        assert_eq!(requirements, QueryDataRequirements::default());
    }

    #[test]
    fn high_selector_requires_script_and_vulnerability_state() {
        let selector = parse_selector(":not(:high)").unwrap();

        let requirements = QueryDataRequirements::for_request(
            Some(&selector),
            false,
            true,
            false,
            QueryFormat::List,
        );

        assert!(requirements.scripts);
        assert!(requirements.vulnerabilities);
        assert!(!requirements.built);
        assert!(!requirements.deprecations);
    }

    #[test]
    fn count_mode_requires_only_counted_dynamic_state() {
        let requirements =
            QueryDataRequirements::for_request(None, true, true, false, QueryFormat::List);

        assert!(requirements.scripts);
        assert!(requirements.vulnerabilities);
        assert!(!requirements.built);
        assert!(!requirements.deprecations);
    }

    #[test]
    fn deprecated_selector_requires_registry_deprecation_state() {
        let selector = parse_selector(":deprecated").unwrap();

        let requirements = QueryDataRequirements::for_request(
            Some(&selector),
            false,
            true,
            false,
            QueryFormat::List,
        );

        assert!(requirements.deprecations);
        assert!(!requirements.scripts);
        assert!(!requirements.built);
        assert!(!requirements.vulnerabilities);
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
