use crate::commands::registry_reads::prepare_routed_read_context;
use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_resolver::{ResolvedPackage, resolve_dependencies_routed};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    packages: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    // Parse packages into deps map: "name@range" or "name" (defaults to *)
    let mut deps: HashMap<String, String> = HashMap::new();
    let mut requested_roots = Vec::with_capacity(packages.len());
    let mut seen_roots = HashSet::with_capacity(packages.len());
    for pkg_str in packages {
        let (name, range) = if let Some(at_pos) = pkg_str.rfind('@') {
            // Careful: @lpm.dev/owner.pkg@1.0.0 — the last @ is the version separator
            if at_pos > 0 {
                (&pkg_str[..at_pos], &pkg_str[at_pos + 1..])
            } else {
                (pkg_str.as_str(), "*")
            }
        } else {
            (pkg_str.as_str(), "*")
        };
        if seen_roots.insert(name.to_string()) {
            requested_roots.push(name.to_string());
        }
        deps.insert(name.to_string(), range.to_string());
    }

    if deps.is_empty() {
        return Err(LpmError::Registry("no packages specified".into()));
    }

    let start = Instant::now();

    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Resolving {} {}",
            install_ui::bold(&deps.len().to_string()),
            install_ui::packages_word(deps.len())
        ));
    }

    let top_level_specs: Vec<String> = deps.keys().cloned().collect();
    let context = prepare_routed_read_context(client, project_dir, &top_level_specs, json_output)?;
    let arc_client = Arc::new(context.client.clone_with_config());

    match resolve_dependencies_routed(arc_client, deps, context.route_table).await {
        Ok(result) => {
            let elapsed = start.elapsed();
            let resolved = &result.packages;

            if json_output {
                let json_pkgs: Vec<serde_json::Value> = resolved
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "package": r.package.to_string(),
                            "version": r.version.to_string(),
                        })
                    })
                    .collect();
                let json = serde_json::json!({
                    "success": true,
                    "packages": json_pkgs,
                    "count": resolved.len(),
                    "elapsed_secs": elapsed.as_secs_f64(),
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
                return Ok(());
            }

            println!();

            for line in render_resolved_tree(resolved, &requested_roots, &result.root_aliases) {
                println!("{line}");
            }
            println!();
            let duration = install_ui::format_duration(elapsed);
            install_ui::done_line(crate::install_ui::terminal_line!(
                "Resolved {} {} in {}",
                install_ui::bold(&resolved.len().to_string()),
                install_ui::packages_word(resolved.len()),
                install_ui::green(&duration)
            ));

            Ok(())
        }
        Err(e) => Err(crate::resolver_error::resolver_error_to_lpm(e)),
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PackageKey {
    name: String,
    version: String,
}

fn render_resolved_tree(
    resolved: &[ResolvedPackage],
    requested_roots: &[String],
    root_aliases: &HashMap<String, String>,
) -> Vec<install_ui::TerminalLine> {
    let mut by_key: HashMap<PackageKey, &ResolvedPackage> = HashMap::with_capacity(resolved.len());
    let mut by_name: HashMap<String, Vec<&ResolvedPackage>> =
        HashMap::with_capacity(resolved.len());

    for package in resolved {
        let name = package.package.canonical_name();
        let version = package.version.to_string();
        by_key
            .entry(PackageKey {
                name: name.clone(),
                version,
            })
            .or_insert(package);
        by_name.entry(name).or_default().push(package);
    }

    let mut lines = Vec::with_capacity(resolved.len());
    for local_name in requested_roots {
        let target_name = root_aliases
            .get(local_name)
            .map(String::as_str)
            .filter(|target| by_name.contains_key(*target))
            .unwrap_or(local_name.as_str());
        let Some(root) = select_root_package(&by_name, target_name) else {
            continue;
        };
        let mut path = HashSet::with_capacity(resolved.len());
        render_tree_node(root, "", &by_key, &mut path, &mut lines);
    }

    if lines.is_empty() {
        for package in resolved {
            lines.push(format_package_label(
                &package.package.canonical_name(),
                &package.version.to_string(),
            ));
        }
    }

    lines
}

fn select_root_package<'a>(
    by_name: &'a HashMap<String, Vec<&'a ResolvedPackage>>,
    target_name: &str,
) -> Option<&'a ResolvedPackage> {
    let candidates = by_name.get(target_name)?;
    candidates
        .iter()
        .copied()
        .find(|package| package.package.context().is_none())
        .or_else(|| candidates.first().copied())
}

fn render_tree_node(
    package: &ResolvedPackage,
    prefix: &str,
    by_key: &HashMap<PackageKey, &ResolvedPackage>,
    path: &mut HashSet<PackageKey>,
    lines: &mut Vec<install_ui::TerminalLine>,
) {
    let name = package.package.canonical_name();
    let version = package.version.to_string();
    let key = PackageKey {
        name: name.clone(),
        version: version.clone(),
    };

    if prefix.is_empty() {
        lines.push(format_package_label(&name, &version));
    }

    if !path.insert(key.clone()) {
        return;
    }

    let mut children = resolved_child_keys(package, by_key);
    children.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));

    for (index, child_key) in children.iter().enumerate() {
        let Some(child) = by_key.get(child_key).copied() else {
            continue;
        };
        let last = index + 1 == children.len();
        let connector = if last { "└─" } else { "├─" };
        let child_label = format_package_label(&child_key.name, &child_key.version);
        let child_prefix = if prefix.is_empty() { "  " } else { prefix };
        let branch = install_ui::dim(&format!("{child_prefix}{connector}"));
        if path.contains(child_key) {
            lines.push(crate::install_ui::terminal_line!(
                "{} {} {}",
                branch,
                child_label,
                install_ui::dim("(circular)")
            ));
            continue;
        }
        lines.push(crate::install_ui::terminal_line!(
            "{} {}",
            branch,
            child_label
        ));
        let next_prefix = format!("{child_prefix}{}", if last { "   " } else { "│  " });
        render_tree_node(child, &next_prefix, by_key, path, lines);
    }

    path.remove(&key);
}

fn resolved_child_keys(
    package: &ResolvedPackage,
    by_key: &HashMap<PackageKey, &ResolvedPackage>,
) -> Vec<PackageKey> {
    let mut children = Vec::with_capacity(package.dependencies.len());
    for (local_name, version) in &package.dependencies {
        let target_name = package
            .aliases
            .get(local_name)
            .map_or(local_name.as_str(), String::as_str);
        let key = PackageKey {
            name: target_name.to_string(),
            version: version.clone(),
        };
        if by_key.contains_key(&key) {
            children.push(key);
        }
    }
    children
}

fn format_package_label(name: &str, version: &str) -> install_ui::TerminalLine {
    crate::install_ui::terminal_line!(
        "{}{}{}",
        name,
        install_ui::dim("@"),
        install_ui::yellow(version)
    )
}
