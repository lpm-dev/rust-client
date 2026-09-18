use clap::Subcommand;
use lpm_common::LpmError;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Subcommand)]
pub enum CatalogCmd {
    /// List catalog entries declared by the workspace root.
    List {
        /// Show only catalog entries no current root/member manifest references.
        #[arg(long)]
        unused: bool,
    },
    /// Show catalog resolution provenance from lpm.lock.
    Show {
        /// Read resolved catalog entries from the lockfile snapshot.
        #[arg(long)]
        resolved: bool,
    },
}

pub fn run(cwd: &Path, action: CatalogCmd, json_output: bool) -> Result<(), LpmError> {
    match action {
        CatalogCmd::List { unused } => list_catalog_entries(cwd, unused, json_output),
        CatalogCmd::Show { resolved } => {
            if !resolved {
                return Err(LpmError::Script(
                    "`lpm catalog show` currently requires --resolved".to_string(),
                ));
            }
            show_resolved_catalog_entries(cwd, json_output)
        }
    }
}

#[derive(Debug)]
struct CatalogContext {
    root_dir: PathBuf,
    catalogs: HashMap<String, HashMap<String, String>>,
    references: lpm_workspace::CatalogReferences,
    importers: HashMap<String, Vec<CatalogRequirement>>,
}

#[derive(Debug, Serialize)]
struct CatalogEntryReport {
    catalog: String,
    package: String,
    specifier: String,
    used: bool,
}

#[derive(Debug, Serialize)]
struct CatalogListEnvelope {
    success: bool,
    mode: &'static str,
    count: usize,
    used_count: usize,
    unused_count: usize,
    entries: Vec<CatalogEntryReport>,
}

#[derive(Debug, Serialize)]
struct ResolvedCatalogEntryReport {
    catalog: String,
    package: String,
    specifier: String,
    version: String,
    reference: String,
}

#[derive(Debug, Serialize)]
struct ResolvedCatalogEnvelope {
    success: bool,
    count: usize,
    entries: Vec<ResolvedCatalogEntryReport>,
}

fn list_catalog_entries(cwd: &Path, unused_only: bool, json_output: bool) -> Result<(), LpmError> {
    let context = load_catalog_context(cwd)?;
    let mut entries = Vec::new();
    let mut used_count = 0usize;
    let mut unused_count = 0usize;

    let mut catalog_names: Vec<&String> = context.catalogs.keys().collect();
    catalog_names.sort_unstable();

    for catalog_name in catalog_names {
        let Some(catalog) = context.catalogs.get(catalog_name) else {
            continue;
        };
        let mut packages: Vec<&String> = catalog.keys().collect();
        packages.sort_unstable();

        for package in packages {
            let used = context
                .references
                .get(catalog_name)
                .is_some_and(|packages| packages.contains(package));
            if used {
                used_count += 1;
            } else {
                unused_count += 1;
            }
            if unused_only && used {
                continue;
            }
            let specifier = catalog
                .get(package)
                .expect("package key was collected from catalog")
                .clone();
            entries.push(CatalogEntryReport {
                catalog: catalog_name.clone(),
                package: package.clone(),
                specifier,
                used,
            });
        }
    }

    if json_output {
        print_json(&CatalogListEnvelope {
            success: true,
            mode: if unused_only { "unused" } else { "all" },
            count: entries.len(),
            used_count,
            unused_count,
            entries,
        })
    } else {
        print_catalog_entries(&entries, unused_only);
        Ok(())
    }
}

fn show_resolved_catalog_entries(cwd: &Path, json_output: bool) -> Result<(), LpmError> {
    let context = load_catalog_context(cwd)?;
    let catalogs = resolved_catalog_snapshots(&context)?;

    let mut entries = Vec::new();
    for (catalog, packages) in &catalogs {
        for (package, entry) in packages {
            entries.push(ResolvedCatalogEntryReport {
                catalog: catalog.clone(),
                package: package.clone(),
                specifier: entry.specifier.clone(),
                version: entry.version.clone(),
                reference: entry.reference.clone(),
            });
        }
    }
    entries.sort_by(|a, b| a.catalog.cmp(&b.catalog).then(a.package.cmp(&b.package)));

    if json_output {
        print_json(&ResolvedCatalogEnvelope {
            success: true,
            count: entries.len(),
            entries,
        })
    } else {
        print_resolved_catalog_entries(&entries);
        Ok(())
    }
}

fn resolved_catalog_snapshots(
    context: &CatalogContext,
) -> Result<lpm_lockfile::CatalogSnapshots, LpmError> {
    let path = context.root_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let lockfile = lpm_lockfile::Lockfile::read_fast(&path).map_err(|error| {
        LpmError::Registry(format!(
            "failed to read catalog snapshot from {}: {error}. Run `lpm install` first.",
            path.display()
        ))
    })?;
    let is_union = !lockfile.workspace_packages.is_empty()
        || lockfile.importers.keys().any(|importer| importer != ".");
    if !is_union {
        validate_catalog_requirements(
            context.importers.get("."),
            &lockfile.catalogs,
            &lockfile.root_resolutions,
            &lockfile.ambient_peer_installs,
            ".",
        )?;
        return Ok(lockfile.catalogs);
    }

    let mut catalogs = lpm_lockfile::CatalogSnapshots::new();
    for (importer, snapshot) in &lockfile.importers {
        validate_catalog_requirements(
            context.importers.get(importer),
            &snapshot.catalog_resolutions,
            &snapshot.root_resolutions,
            &snapshot.ambient_peer_installs,
            importer,
        )?;
        for (catalog, packages) in &snapshot.catalog_resolutions {
            let merged = catalogs.entry(catalog.clone()).or_default();
            for (package, entry) in packages {
                let mut entry = entry.clone();
                if catalog == "default"
                    && matches!(entry.reference.as_str(), "catalog:" | "catalog:default")
                {
                    entry.reference = "catalog:".into();
                }
                if let Some(existing) = merged.get(package)
                    && existing != &entry
                {
                    return Err(LpmError::Registry(format!(
                        "lpm.lock has conflicting resolved catalog snapshots for {catalog}/{package} across workspace importers (including {importer})"
                    )));
                }
                merged.insert(package.clone(), entry);
            }
        }
    }
    Ok(catalogs)
}

#[derive(Debug)]
struct CatalogRequirement {
    catalog: String,
    package: String,
    optional: bool,
}

fn catalog_requirements(package: &lpm_workspace::PackageJson) -> Vec<CatalogRequirement> {
    let mut dependencies = HashMap::with_capacity(
        package.dependencies.len()
            + package.dev_dependencies.len()
            + package.optional_dependencies.len(),
    );
    dependencies.extend(package.dev_dependencies.iter());
    dependencies.extend(package.dependencies.iter());
    dependencies.extend(package.optional_dependencies.iter());
    dependencies
        .into_iter()
        .filter_map(|(name, reference)| {
            let catalog = reference.strip_prefix("catalog:")?;
            Some(CatalogRequirement {
                catalog: if catalog.is_empty() {
                    "default".into()
                } else {
                    catalog.into()
                },
                package: name.clone(),
                optional: package.optional_dependencies.contains_key(name),
            })
        })
        .collect()
}

fn validate_catalog_requirements(
    requirements: Option<&Vec<CatalogRequirement>>,
    snapshots: &lpm_lockfile::CatalogSnapshots,
    roots: &lpm_lockfile::RootResolutions,
    ambient_peers: &[String],
    importer: &str,
) -> Result<(), LpmError> {
    let mut missing = Vec::new();
    for requirement in requirements.into_iter().flatten() {
        if requirement.optional
            && (!roots.contains_key(&requirement.package)
                || ambient_peers.contains(&requirement.package))
        {
            continue;
        }
        if !snapshots
            .get(&requirement.catalog)
            .is_some_and(|entries| entries.contains_key(&requirement.package))
        {
            missing.push(format!("{}/{}", requirement.catalog, requirement.package));
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    missing.sort_unstable();
    Err(LpmError::Registry(format!(
        "lpm.lock is missing resolved catalog snapshots for {} in importer {importer}. Run `lpm install` to refresh the lockfile.",
        missing.join(", ")
    )))
}

fn load_catalog_context(cwd: &Path) -> Result<CatalogContext, LpmError> {
    match lpm_workspace::discover_workspace(cwd)
        .map_err(|e| LpmError::Registry(format!("failed to discover workspace catalogs: {e}")))?
    {
        Some(workspace) => {
            let mut references = lpm_workspace::CatalogReferences::new();
            let mut importers = HashMap::with_capacity(workspace.members.len() + 1);
            importers.insert(".".into(), catalog_requirements(&workspace.root_package));
            lpm_workspace::collect_catalog_references(&workspace.root_package, &mut references);
            for member in &workspace.members {
                lpm_workspace::collect_catalog_references(&member.package, &mut references);
                let importer = member
                    .path
                    .strip_prefix(&workspace.root)
                    .map_err(|error| LpmError::Registry(error.to_string()))?;
                importers.insert(
                    importer.to_string_lossy().replace('\\', "/"),
                    catalog_requirements(&member.package),
                );
            }
            Ok(CatalogContext {
                importers,
                root_dir: workspace.root,
                catalogs: workspace.root_package.catalogs,
                references,
            })
        }
        None => {
            let package_json_path = cwd.join("package.json");
            let package = lpm_workspace::read_package_json(&package_json_path).map_err(|e| {
                LpmError::Registry(format!(
                    "failed to read package manifest {}: {e}",
                    package_json_path.display()
                ))
            })?;
            let mut references = lpm_workspace::CatalogReferences::new();
            lpm_workspace::collect_catalog_references(&package, &mut references);
            Ok(CatalogContext {
                importers: HashMap::from([(".".into(), catalog_requirements(&package))]),
                root_dir: cwd.to_path_buf(),
                catalogs: package.catalogs,
                references,
            })
        }
    }
}

fn print_catalog_entries(entries: &[CatalogEntryReport], unused_only: bool) {
    if entries.is_empty() {
        if unused_only {
            println!("No unused catalog entries.");
        } else {
            println!("No catalog entries.");
        }
        return;
    }

    for entry in entries {
        let status = if entry.used { "used" } else { "unused" };
        println!(
            "{}",
            crate::install_ui::terminal_line!(
                "{} {} {} {}",
                &entry.catalog,
                &entry.package,
                &entry.specifier,
                status
            )
        );
    }
}

fn print_resolved_catalog_entries(entries: &[ResolvedCatalogEntryReport]) {
    if entries.is_empty() {
        println!("No resolved catalog entries in lpm.lock.");
        return;
    }

    for entry in entries {
        println!(
            "{}",
            crate::install_ui::terminal_line!(
                "{} {} {} -> {} ({})",
                &entry.catalog,
                &entry.package,
                &entry.reference,
                &entry.version,
                &entry.specifier
            )
        );
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<(), LpmError> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| LpmError::Script(format!("failed to serialize catalog output: {e}")))?;
    println!("{json}");
    Ok(())
}
