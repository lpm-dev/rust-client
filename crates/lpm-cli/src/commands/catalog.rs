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
    let lockfile_path = context.root_dir.join("lpm.lock");
    let lockfile = lpm_lockfile::Lockfile::read_fast(&lockfile_path).map_err(|error| {
        LpmError::Registry(format!(
            "failed to read catalog snapshot from {}: {error}. Run `lpm install` first.",
            lockfile_path.display()
        ))
    })?;

    let missing = missing_catalog_snapshot_references(&context.references, &lockfile.catalogs);
    if !missing.is_empty() {
        return Err(LpmError::Registry(format!(
            "lpm.lock is missing resolved catalog snapshots for {}. Run `lpm install` to refresh the lockfile.",
            missing.join(", ")
        )));
    }

    let mut entries = Vec::new();
    for (catalog, packages) in &lockfile.catalogs {
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

fn missing_catalog_snapshot_references(
    references: &lpm_workspace::CatalogReferences,
    snapshots: &lpm_lockfile::CatalogSnapshots,
) -> Vec<String> {
    let mut missing = Vec::new();
    for (catalog, packages) in references {
        for package in packages {
            if !snapshots
                .get(catalog)
                .is_some_and(|entries| entries.contains_key(package))
            {
                missing.push(format!("{catalog}/{package}"));
            }
        }
    }
    missing
}

fn load_catalog_context(cwd: &Path) -> Result<CatalogContext, LpmError> {
    match lpm_workspace::discover_workspace(cwd)
        .map_err(|e| LpmError::Registry(format!("failed to discover workspace catalogs: {e}")))?
    {
        Some(workspace) => {
            let mut references = lpm_workspace::CatalogReferences::new();
            lpm_workspace::collect_catalog_references(&workspace.root_package, &mut references);
            for member in &workspace.members {
                lpm_workspace::collect_catalog_references(&member.package, &mut references);
            }
            Ok(CatalogContext {
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
