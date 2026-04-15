//! `lpm global` — read-only commands against the global manifest.
//!
//! Phase 37 M2.5 ships `list`, `bin`, `path`. The full surface
//! (`install`, `uninstall`, `update`, `remove`) lands in M3 once the
//! install pipeline is wired through `IsolatedInstall::persistent`.
//! Because reads do not need a lock, the M2 commands work straight off
//! the manifest file — they're a useful smoke test of the schema even
//! before any global install can be performed.

use crate::output;
use lpm_common::{LpmError, LpmRoot, format_bytes};
use lpm_global::{GlobalManifest, PackageEntry};
use owo_colors::OwoColorize;
use std::path::Path;

/// Subcommands of `lpm global`. Defined here (not in `main.rs`) so the
/// dispatcher and the implementation share the same type without needing
/// `crate::main::*` imports — `main` is a binary entry point and isn't
/// addressable as a module from sibling files.
#[derive(Debug, clap::Subcommand)]
pub enum GlobalCmd {
    /// List globally-installed packages with their active versions and exposed commands.
    List {
        /// Compare each install's resolved version against the registry
        /// and flag packages with newer versions available. Reserved
        /// for phase 37 M3: invoking with this flag today errors loudly
        /// rather than silently no-opping (avoids the misleading
        /// "no outdated packages" output before the implementation
        /// lands).
        #[arg(long)]
        outdated: bool,

        /// Show install date, on-disk size, and root path per package.
        #[arg(long)]
        verbose: bool,
    },

    /// Print the directory `~/.lpm/bin/` (the dir where global-install
    /// shims live; what users add to their PATH).
    Bin,

    /// Print the install root for one specific globally-installed package.
    Path {
        /// Package name (e.g. `eslint`, `@lpm.dev/owner.tool`).
        package: String,
    },
}

pub async fn run(action: GlobalCmd, json_output: bool) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    let manifest = lpm_global::read_for(&root)?;

    match action {
        GlobalCmd::List { outdated, verbose } => {
            run_list(&root, &manifest, outdated, verbose, json_output)
        }
        GlobalCmd::Bin => run_bin(&root, json_output),
        GlobalCmd::Path { package } => run_path(&root, &manifest, &package, json_output),
    }
}

// ─── list ──────────────────────────────────────────────────────────────

fn run_list(
    root: &LpmRoot,
    manifest: &GlobalManifest,
    outdated: bool,
    verbose: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if outdated {
        // Reserved for M3 — needs registry round-trips against each
        // package's `saved_spec`. Don't silently no-op; tell the user
        // exactly when the flag goes live.
        return Err(LpmError::Script(
            "`--outdated` lands in phase 37 M3 (needs registry comparison \
             against each install's saved_spec). Use `lpm global list` for \
             now to see installed versions."
                .into(),
        ));
    }

    if json_output {
        emit_list_json(root, manifest, verbose);
    } else {
        emit_list_human(root, manifest, verbose);
    }
    Ok(())
}

fn emit_list_json(root: &LpmRoot, manifest: &GlobalManifest, verbose: bool) {
    let entries: Vec<_> = manifest
        .packages
        .iter()
        .map(|(name, e)| package_to_json(root, name, e, manifest, verbose))
        .collect();
    let body = serde_json::json!({
        "success": true,
        "count": manifest.packages.len(),
        "packages": entries,
    });
    println!("{}", serde_json::to_string_pretty(&body).unwrap());
}

fn package_to_json(
    root: &LpmRoot,
    name: &str,
    entry: &PackageEntry,
    manifest: &GlobalManifest,
    verbose: bool,
) -> serde_json::Value {
    let commands = enrich_commands(name, entry, manifest);
    let mut obj = serde_json::json!({
        "name": name,
        "version": entry.resolved,
        "saved_spec": entry.saved_spec,
        "source": entry.source,
        "commands": commands,
    });
    if verbose {
        let install_root = root.global_root().join(&entry.root);
        let bytes = dir_size(&install_root).unwrap_or(0);
        obj["installed_at"] = serde_json::Value::String(entry.installed_at.to_rfc3339());
        obj["bytes_on_disk"] = serde_json::json!(bytes);
        obj["size_on_disk"] = serde_json::Value::String(format_bytes(bytes));
        obj["root"] = serde_json::Value::String(install_root.display().to_string());
    }
    obj
}

fn emit_list_human(root: &LpmRoot, manifest: &GlobalManifest, verbose: bool) {
    if manifest.packages.is_empty() {
        output::info("No globally-installed packages.");
        if !root.global_manifest().exists() {
            output::info(&format!(
                "Manifest does not exist yet at {}. Try `lpm install -g <pkg>` once M3 lands.",
                root.global_manifest().display()
            ));
        }
        return;
    }

    println!();
    println!(
        "  {} global package{}:",
        manifest.packages.len().to_string().bold(),
        if manifest.packages.len() == 1 {
            ""
        } else {
            "s"
        }
    );
    for (name, entry) in &manifest.packages {
        let commands = enrich_commands(name, entry, manifest);
        let cmds_str = if commands.is_empty() {
            "(no commands)".dimmed().to_string()
        } else {
            commands.join(", ")
        };
        println!(
            "    {} {} \u{2014} {}",
            name.bold(),
            format!("@{}", entry.resolved).dimmed(),
            cmds_str
        );
        if verbose {
            let install_root = root.global_root().join(&entry.root);
            let bytes = dir_size(&install_root).unwrap_or(0);
            println!(
                "        spec: {}    installed: {}    size: {}",
                entry.saved_spec.dimmed(),
                entry.installed_at.format("%Y-%m-%d").to_string().dimmed(),
                format_bytes(bytes).dimmed()
            );
            println!(
                "        root: {}",
                install_root.display().to_string().dimmed()
            );
        }
    }
    if !manifest.aliases.is_empty() {
        println!();
        println!(
            "  {} alias{}:",
            manifest.aliases.len().to_string().bold(),
            if manifest.aliases.len() == 1 {
                ""
            } else {
                "es"
            }
        );
        for (alias, entry) in &manifest.aliases {
            println!(
                "    {} \u{2192} {}'s {}",
                alias.bold(),
                entry.package,
                entry.bin.dimmed()
            );
        }
    }
    println!();
}

/// Annotate command list with `(alias of X)` when an alias maps onto
/// a package's declared bin from another package. Per the plan: a
/// package's row keeps its declared commands; aliases live in the
/// `[aliases]` table with their owning bin.
fn enrich_commands(pkg_name: &str, entry: &PackageEntry, manifest: &GlobalManifest) -> Vec<String> {
    let mut out: Vec<String> = entry.commands.clone();
    for (alias_name, alias_entry) in &manifest.aliases {
        if alias_entry.package == pkg_name {
            out.push(format!("{alias_name} (alias of {})", alias_entry.bin));
        }
    }
    out
}

// ─── bin ───────────────────────────────────────────────────────────────

fn run_bin(root: &LpmRoot, json_output: bool) -> Result<(), LpmError> {
    let path = root.bin_dir();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "path": path.display().to_string(),
            }))
            .unwrap()
        );
    } else {
        println!("{}", path.display());
    }
    Ok(())
}

// ─── path ──────────────────────────────────────────────────────────────

fn run_path(
    root: &LpmRoot,
    manifest: &GlobalManifest,
    package: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let entry = manifest.packages.get(package).ok_or_else(|| {
        LpmError::Script(format!(
            "package '{package}' is not globally installed. Run `lpm global list` to see installed packages."
        ))
    })?;
    let install_root = root.global_root().join(&entry.root);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "package": package,
                "version": entry.resolved,
                "path": install_root.display().to_string(),
            }))
            .unwrap()
        );
    } else {
        println!("{}", install_root.display());
    }
    Ok(())
}

// ─── helpers ───────────────────────────────────────────────────────────

fn dir_size(path: &Path) -> std::io::Result<u64> {
    let mut total: u64 = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            total = total.saturating_add(dir_size(&entry.path())?);
        } else if ft.is_file() {
            total = total.saturating_add(entry.metadata()?.len());
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lpm_global::{AliasEntry, PackageSource, write_for};
    use tempfile::TempDir;

    fn seed(root: &LpmRoot) -> GlobalManifest {
        let mut m = GlobalManifest::default();
        m.packages.insert(
            "eslint".into(),
            PackageEntry {
                saved_spec: "^9".into(),
                resolved: "9.24.0".into(),
                integrity: "sha512-x".into(),
                source: PackageSource::UpstreamNpm,
                installed_at: Utc::now(),
                root: "installs/eslint@9.24.0".into(),
                commands: vec!["eslint".into()],
            },
        );
        m.aliases.insert(
            "srv".into(),
            AliasEntry {
                package: "eslint".into(),
                bin: "serve".into(),
            },
        );
        write_for(root, &m).unwrap();
        m
    }

    #[tokio::test]
    async fn list_handles_empty_manifest() {
        let tmp = TempDir::new().unwrap();
        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        let r = run(
            GlobalCmd::List {
                outdated: false,
                verbose: false,
            },
            true,
        )
        .await;
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn list_outdated_returns_m3_pending_error() {
        let tmp = TempDir::new().unwrap();
        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        let r = run(
            GlobalCmd::List {
                outdated: true,
                verbose: false,
            },
            true,
        )
        .await;
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
        let err = r.unwrap_err();
        assert!(format!("{err}").contains("M3"));
    }

    #[tokio::test]
    async fn list_emits_seeded_packages() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed(&root);

        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        let r = run(
            GlobalCmd::List {
                outdated: false,
                verbose: true,
            },
            true,
        )
        .await;
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn bin_prints_bin_dir() {
        let tmp = TempDir::new().unwrap();
        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        let r = run(GlobalCmd::Bin, true).await;
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn path_succeeds_for_known_package() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed(&root);

        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        let r = run(
            GlobalCmd::Path {
                package: "eslint".into(),
            },
            true,
        )
        .await;
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn path_errors_for_unknown_package() {
        let tmp = TempDir::new().unwrap();
        unsafe {
            std::env::set_var("LPM_HOME", tmp.path());
        }
        let r = run(
            GlobalCmd::Path {
                package: "does-not-exist".into(),
            },
            true,
        )
        .await;
        unsafe {
            std::env::remove_var("LPM_HOME");
        }
        let err = r.unwrap_err();
        assert!(format!("{err}").contains("not globally installed"));
    }

    #[test]
    fn enrich_commands_appends_aliases_owned_by_package() {
        let mut m = GlobalManifest::default();
        let entry = PackageEntry {
            saved_spec: "^1".into(),
            resolved: "1.0.0".into(),
            integrity: "sha512-z".into(),
            source: PackageSource::LpmDev,
            installed_at: Utc::now(),
            root: "installs/x@1.0.0".into(),
            commands: vec!["x".into()],
        };
        m.packages.insert("x".into(), entry.clone());
        m.aliases.insert(
            "y".into(),
            AliasEntry {
                package: "x".into(),
                bin: "x".into(),
            },
        );
        let cmds = enrich_commands("x", &entry, &m);
        assert_eq!(cmds.len(), 2);
        assert!(cmds.iter().any(|c| c.contains("y (alias of x)")));
    }
}
