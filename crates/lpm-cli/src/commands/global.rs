//! `lpm global` — commands against the global manifest.
//!
//! Subcommands: `list` (with `--outdated`/`--verbose`), `bin`,
//! `path <pkg>`, `link [path]`, `unlink <pkg>`, `remove <pkg>`
//! (= `lpm uninstall -g <pkg>`), `update [<pkg>[@<spec>]]` (with `--dry-run`).
//! Read-only commands (`list`, `bin`, `path`) do not acquire a lock.

use crate::install_ui;
use chrono::Utc;
use lpm_common::color::Painted;
use lpm_common::{LpmError, LpmRoot, format_bytes, sanitize_for_terminal, with_exclusive_lock};
use lpm_global::{
    GlobalManifest, PackageEntry, PackageSource, Shim, artifacts_complete, emit_shim,
    find_command_collisions, remove_shim,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const LOCAL_LINK_SPEC_PREFIX: &str = "link:";

/// Subcommands of `lpm global`. Defined here (not in `main.rs`) so the
/// dispatcher and the implementation share the same type without needing
/// `crate::main::*` imports — `main` is a binary entry point and isn't
/// addressable as a module from sibling files.
#[derive(Debug, clap::Subcommand)]
pub enum GlobalCmd {
    /// List globally-installed packages with their active versions and exposed commands.
    List {
        /// Compare each install's resolved version against the registry
        /// and flag packages with newer versions available under the
        /// persisted `saved_spec`.
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

    /// Link a local package's bin entries into the global PATH surface.
    Link {
        /// Local package directory. Defaults to the current directory.
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
    },

    /// Remove a local package link created with `lpm global link`.
    Unlink {
        /// Package name (e.g. `my-cli`, `@scope/tool`).
        package: String,
    },

    /// Remove a globally-installed package.
    ///
    /// Equivalent to `lpm uninstall -g <pkg>` — both invocations route
    /// through the same `uninstall_global` implementation.
    Remove {
        /// Package name (e.g. `eslint`, `@lpm.dev/owner.tool`).
        package: String,
    },

    /// Update a globally-installed package (or all of them).
    ///
    /// With no argument: re-resolve every globally-installed package
    /// against its persisted `saved_spec` and upgrade any that have
    /// a newer matching version available. precedence applies
    /// — preserved ranges, dist-tag re-pin, etc.
    ///
    /// With `<pkg>` (no version): same flow scoped to one package.
    ///
    /// With `<pkg>@<spec>`: rewrite the saved_spec
    /// using the `decide_saved_dependency_spec`, then upgrade.
    /// Same precedence as `lpm install <pkg>@<spec>` in a project.
    ///
    /// Use `--dry-run` to print the upgrade plan without making any
    /// state changes.
    Update {
        /// Optional package spec. Bare invocation iterates every
        /// globally-installed package. `<pkg>` re-resolves one;
        /// `<pkg>@<spec>` rewrites the saved_spec and resolves.
        package: Option<String>,

        /// Print the upgrade plan without doing the work.
        #[arg(long)]
        dry_run: bool,
    },
}

pub async fn run(
    client: &lpm_registry::RegistryClient,
    action: GlobalCmd,
    json_output: bool,
) -> Result<(), LpmError> {
    let root = LpmRoot::from_env()?;
    let manifest = lpm_global::read_for(&root)?;

    match action {
        GlobalCmd::List {
            outdated: true,
            verbose,
        } => run_list_outdated(client, &root, &manifest, verbose, json_output).await,
        GlobalCmd::List { outdated, verbose } => {
            run_list(&root, &manifest, outdated, verbose, json_output);
            Ok(())
        }
        GlobalCmd::Bin => {
            run_bin(&root, json_output);
            Ok(())
        }
        GlobalCmd::Path { package } => run_path(&root, &manifest, &package, json_output),
        GlobalCmd::Link { path } => run_link(&root, path.as_deref(), json_output),
        GlobalCmd::Unlink { package } => run_unlink(&root, &package, json_output),
        // `lpm global remove` and `lpm uninstall -g` are two surfaces
        // for the same operation. Both route through the
        // `uninstall_global` pipeline.
        GlobalCmd::Remove { package } => {
            crate::commands::uninstall_global::run(&package, json_output).await
        }
        GlobalCmd::Update { package, dry_run } => {
            crate::commands::update_global::run(client, package.as_deref(), dry_run, json_output)
                .await
        }
    }
}

// ─── list ──────────────────────────────────────────────────────────────

fn run_list(
    root: &LpmRoot,
    manifest: &GlobalManifest,
    _outdated: bool,
    verbose: bool,
    json_output: bool,
) {
    // `outdated == true` is routed through `run_list_outdated` in the
    // dispatch match — this function only sees the non-outdated path.
    if json_output {
        emit_list_json(root, manifest, verbose);
    } else {
        emit_list_human(root, manifest, verbose);
    }
}

// ─── lpm global list --outdated ─────────────────────────────────

/// compare each globally-installed package's resolved
/// version against the highest version the registry exposes under the
/// package's persisted `saved_spec`. Report packages whose registry
/// has something newer.
/// Schema: each outdated row carries (current, latest) versions + the
/// saved_spec used for comparison. The caller can pipe `--json` output
/// into a script that auto-runs `lpm global update <pkg>` for each
/// outdated row.
async fn run_list_outdated(
    client: &lpm_registry::RegistryClient,
    _root: &LpmRoot,
    manifest: &GlobalManifest,
    verbose: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    if manifest.packages.is_empty() {
        // No globally-installed packages → nothing to check. Matches
        // the shape of `run_list` on an empty manifest but uses a
        // clearer "nothing to compare" message in human mode.
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "outdated": [],
                    "up_to_date": [],
                    "unresolved": [],
                    "count_outdated": 0,
                    "count_unresolved": 0,
                }))
                .unwrap()
            );
        } else {
            install_ui::warn("No globally-installed packages");
        }
        return Ok(());
    }

    let package_count = manifest.packages.len();
    let mut local_links = Vec::with_capacity(package_count);
    let mut lpm_names = Vec::with_capacity(package_count);
    let mut npm_names = Vec::with_capacity(package_count);
    for (name, entry) in &manifest.packages {
        match entry.source {
            PackageSource::LocalLink => local_links.push(name.clone()),
            _ if lpm_common::package_name::is_lpm_package(name) => {
                lpm_names.push(name.clone());
            }
            _ => npm_names.push(name.clone()),
        }
    }

    if lpm_names.is_empty() && npm_names.is_empty() {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "outdated": [],
                    "up_to_date": [],
                    "unresolved": [],
                    "skipped_local_links": local_links,
                    "count_outdated": 0,
                    "count_unresolved": 0,
                }))
                .unwrap()
            );
        } else {
            install_ui::done(&format!(
                "No registry-backed global packages to check ({} local link{} skipped).",
                local_links.len(),
                if local_links.len() == 1 { "" } else { "s" },
            ));
        }
        return Ok(());
    }

    let mut metadata: HashMap<String, lpm_registry::PackageMetadata> =
        HashMap::with_capacity(lpm_names.len() + npm_names.len());
    let mut metadata_errors: HashMap<String, String> = HashMap::new();

    if !lpm_names.is_empty() {
        match client.batch_metadata(&lpm_names).await {
            Ok(batch) => metadata.extend(batch),
            Err(e) => {
                return Err(LpmError::Script(format!(
                    "batch metadata fetch failed — cannot compute outdated: {e}"
                )));
            }
        }
    }

    let npm_fetches = npm_names.iter().map(|name| async move {
        (
            name.clone(),
            client.get_npm_package_metadata(name.as_str()).await,
        )
    });
    for (name, result) in futures::future::join_all(npm_fetches).await {
        match result {
            Ok(package_metadata) => {
                metadata.insert(name, package_metadata);
            }
            Err(error) => {
                metadata_errors.insert(name, error.to_string());
            }
        }
    }

    let mut outdated: Vec<OutdatedRow> = Vec::new();
    let mut up_to_date: Vec<String> = Vec::new();
    let mut unresolved: Vec<UnresolvedRow> = Vec::new();

    for (name, entry) in &manifest.packages {
        if entry.source == PackageSource::LocalLink {
            continue;
        }
        let Some(meta) = metadata.get(name) else {
            unresolved.push(UnresolvedRow {
                package: name.clone(),
                reason: metadata_errors.get(name).cloned().unwrap_or_else(|| {
                    "no registry metadata returned for this package".to_string()
                }),
            });
            continue;
        };
        let latest = match pick_latest_matching(meta, &entry.saved_spec) {
            Ok(v) => v,
            Err(reason) => {
                unresolved.push(UnresolvedRow {
                    package: name.clone(),
                    reason,
                });
                continue;
            }
        };
        if latest == entry.resolved {
            up_to_date.push(name.clone());
        } else {
            let absolute_latest = pick_absolute_latest(meta).unwrap_or_else(|| latest.clone());
            outdated.push(OutdatedRow {
                package: name.clone(),
                current: entry.resolved.clone(),
                wanted: latest,
                latest: absolute_latest,
                saved_spec: entry.saved_spec.clone(),
                bins: enrich_commands(name, entry, manifest),
            });
        }
    }
    outdated.sort_by(|a, b| a.package.cmp(&b.package));
    up_to_date.sort();
    unresolved.sort_by(|a, b| a.package.cmp(&b.package));

    if json_output {
        emit_outdated_json(&outdated, &up_to_date, &unresolved, &local_links);
    } else {
        emit_outdated_human(&outdated, &up_to_date, &unresolved, &local_links, verbose);
    }
    if !unresolved.is_empty() {
        return Err(LpmError::ExitCode(1));
    }
    Ok(())
}

/// One row in the `--outdated` report where the registry has a newer
/// version that satisfies the persisted `saved_spec`.
#[derive(Debug, Clone)]
struct OutdatedRow {
    package: String,
    current: String,
    wanted: String,
    latest: String,
    saved_spec: String,
    bins: Vec<String>,
}

/// A globally-installed package that could not be compared — missing
/// from the batch response, or `saved_spec` had no matching version.
#[derive(Debug, Clone)]
struct UnresolvedRow {
    package: String,
    reason: String,
}

/// Pick the highest registry version that satisfies `saved_spec`.
/// Same resolver-precedence as `update_global::pick_version` but
/// inlined here to keep `lpm global list --outdated` independent of `update_global` internals.
fn pick_latest_matching(
    meta: &lpm_registry::PackageMetadata,
    saved_spec: &str,
) -> Result<String, String> {
    // Dist-tag fast path: `latest`, `next`, etc. can appear in
    // saved_spec directly (e.g. bulk-install default). Mirrors
    // update_global.
    if let Some(v) = meta.dist_tags.get(saved_spec) {
        return Ok(v.clone());
    }
    // Exact pins that disappeared upstream should surface as unresolved,
    // not silently report up-to-date.
    if lpm_semver::Version::parse(saved_spec).is_ok() {
        if meta.versions.contains_key(saved_spec) {
            return Ok(saved_spec.to_string());
        }
        return Err(format!(
            "registry no longer serves the exact-pinned version '{saved_spec}' for '{}' — \
             the version may have been yanked or deleted upstream",
            meta.name
        ));
    }
    // Wildcard: highest version, period.
    if saved_spec == "*" {
        let mut versions: Vec<lpm_semver::Version> = meta
            .versions
            .keys()
            .filter_map(|s| lpm_semver::Version::parse(s).ok())
            .collect();
        if versions.is_empty() {
            return Err(format!("no parseable versions for '{}'", meta.name));
        }
        versions.sort();
        return Ok(versions.last().unwrap().to_string());
    }
    // Range: max-satisfying.
    let req = lpm_semver::VersionReq::parse(saved_spec)
        .map_err(|e| format!("saved_spec {saved_spec:?} is not a valid range: {e}"))?;
    let versions: Vec<lpm_semver::Version> = meta
        .versions
        .keys()
        .filter_map(|s| lpm_semver::Version::parse(s).ok())
        .collect();
    let refs: Vec<&lpm_semver::Version> = versions.iter().collect();
    lpm_semver::max_satisfying(&refs, &req)
        .map(|v| v.to_string())
        .ok_or_else(|| format!("no version of '{}' satisfies '{}'", meta.name, saved_spec))
}

fn pick_absolute_latest(meta: &lpm_registry::PackageMetadata) -> Option<String> {
    meta.dist_tags.get("latest").cloned().or_else(|| {
        meta.versions
            .keys()
            .filter_map(|s| lpm_semver::Version::parse(s).ok())
            .max()
            .map(|v| v.to_string())
    })
}

fn emit_outdated_json(
    outdated: &[OutdatedRow],
    up_to_date: &[String],
    unresolved: &[UnresolvedRow],
    local_links: &[String],
) {
    let out_entries: Vec<_> = outdated
        .iter()
        .map(|r| {
            serde_json::json!({
                "package": r.package,
                "current": r.current,
                "latest": r.wanted,
                "saved_spec": r.saved_spec,
            })
        })
        .collect();
    let unresolved_entries: Vec<_> = unresolved
        .iter()
        .map(|r| serde_json::json!({"package": r.package, "reason": r.reason}))
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "success": unresolved.is_empty(),
            "count_outdated": outdated.len(),
            "count_unresolved": unresolved.len(),
            "outdated": out_entries,
            "up_to_date": up_to_date,
            "unresolved": unresolved_entries,
            "skipped_local_links": local_links,
        }))
        .unwrap()
    );
}

fn emit_outdated_human(
    outdated: &[OutdatedRow],
    up_to_date: &[String],
    unresolved: &[UnresolvedRow],
    local_links: &[String],
    verbose: bool,
) {
    if outdated.is_empty() && unresolved.is_empty() {
        install_ui::done(&format!(
            "All {} registry-backed global package{} are up-to-date.",
            up_to_date.len(),
            if up_to_date.len() == 1 { "" } else { "s" },
        ));
        if !local_links.is_empty() && verbose {
            let names_safe: Vec<String> = local_links
                .iter()
                .map(|n| sanitize_for_terminal(n))
                .collect();
            install_ui::phase(&format!(
                "{} local link{} skipped: {}",
                local_links.len(),
                if local_links.len() == 1 { "" } else { "s" },
                names_safe.join(", ").dimmed(),
            ));
        }
        return;
    }

    if !outdated.is_empty() {
        println!();
        println!("  {} outdated:", outdated.len().to_string().bold(),);
        let widths = OutdatedTableWidths::for_rows(outdated);
        println!(
            "  {}  {}  {}  {}  {}",
            format!("{:<width$}", "Package", width = widths.package).dimmed(),
            format!("{:<width$}", "Current", width = widths.current).dimmed(),
            format!("{:<width$}", "Wanted", width = widths.wanted).dimmed(),
            format!("{:<width$}", "Latest", width = widths.latest).dimmed(),
            "Bins".dimmed()
        );
        for r in outdated {
            let package_safe = sanitize_for_terminal(&r.package);
            let current_safe = sanitize_for_terminal(&r.current);
            let wanted_safe = sanitize_for_terminal(&r.wanted);
            let latest_safe = sanitize_for_terminal(&r.latest);
            let bins_safe = format_bins(&r.bins);
            let package_col = format!("{package_safe:<width$}", width = widths.package);
            let current_col = format!("{current_safe:<width$}", width = widths.current).dimmed();
            let wanted_col = format!("{wanted_safe:<width$}", width = widths.wanted).green();
            let latest_raw = format!("{latest_safe:<width$}", width = widths.latest);
            let latest_col = style_latest_version(&latest_raw, &r.wanted, &r.latest);
            let spec_suffix = if verbose {
                let spec_safe = sanitize_for_terminal(&r.saved_spec);
                format!("  (spec: {})", spec_safe.dimmed())
            } else {
                String::new()
            };
            println!(
                "  {}  {}  {}  {}  {}{}",
                package_col,
                current_col,
                wanted_col,
                latest_col,
                bins_safe.dimmed(),
                spec_suffix,
            );
        }
        println!();
        install_ui::phase(
            "Run `lpm global update <pkg>` to upgrade one, or \
             `lpm global update` to upgrade every outdated install.",
        );
        println!();
    }
    if !unresolved.is_empty() {
        install_ui::warn(&format!(
            "{} package{} could not be compared:",
            unresolved.len(),
            if unresolved.len() == 1 { "" } else { "s" },
        ));
        for r in unresolved {
            let package_safe = sanitize_for_terminal(&r.package);
            let reason_safe = sanitize_for_terminal(&r.reason);
            println!("    {}: {}", package_safe.bold(), reason_safe.dimmed());
        }
        println!();
    }
    if !up_to_date.is_empty() && verbose {
        let names_safe: Vec<String> = up_to_date
            .iter()
            .map(|n| sanitize_for_terminal(n))
            .collect();
        install_ui::phase(&format!(
            "{} up-to-date: {}",
            up_to_date.len(),
            names_safe.join(", ").dimmed(),
        ));
    }
}

struct OutdatedTableWidths {
    package: usize,
    current: usize,
    wanted: usize,
    latest: usize,
}

impl OutdatedTableWidths {
    fn for_rows(rows: &[OutdatedRow]) -> Self {
        let mut widths = Self {
            package: "Package".len(),
            current: "Current".len(),
            wanted: "Wanted".len(),
            latest: "Latest".len(),
        };
        for row in rows {
            widths.package = widths
                .package
                .max(sanitize_for_terminal(&row.package).len());
            widths.current = widths
                .current
                .max(sanitize_for_terminal(&row.current).len());
            widths.wanted = widths.wanted.max(sanitize_for_terminal(&row.wanted).len());
            widths.latest = widths.latest.max(sanitize_for_terminal(&row.latest).len());
        }
        widths
    }
}

fn format_bins(bins: &[String]) -> String {
    if bins.is_empty() {
        return "-".to_string();
    }
    bins.iter()
        .map(|bin| sanitize_for_terminal(bin))
        .collect::<Vec<_>>()
        .join(", ")
}

fn style_latest_version(padded_latest: &str, wanted: &str, latest: &str) -> String {
    if latest == wanted {
        return padded_latest.yellow();
    }
    let wanted_major = lpm_semver::Version::parse(wanted).ok().map(|v| v.major());
    let latest_major = lpm_semver::Version::parse(latest).ok().map(|v| v.major());
    if matches!((wanted_major, latest_major), (Some(wanted), Some(latest)) if latest > wanted) {
        padded_latest.red()
    } else {
        padded_latest.yellow()
    }
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
        if let Some(path) = linked_source_path(entry) {
            obj["linked_path"] = serde_json::Value::String(path.to_string());
        }
    }
    obj
}

fn emit_list_human(root: &LpmRoot, manifest: &GlobalManifest, verbose: bool) {
    if manifest.packages.is_empty() {
        install_ui::warn("No globally-installed packages");
        if !root.global_manifest().exists() {
            install_ui::phase(&format!(
                "Run `lpm install -g <pkg>` to install one. Manifest lives at {}.",
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
            commands
                .iter()
                .map(|c| sanitize_for_terminal(c))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let name_safe = sanitize_for_terminal(name);
        let resolved_safe = sanitize_for_terminal(&entry.resolved);
        println!(
            "    {} {} \u{2014} {}",
            name_safe.bold(),
            format!("@{resolved_safe}").dimmed(),
            cmds_str
        );
        if verbose {
            let install_root = root.global_root().join(&entry.root);
            let bytes = dir_size(&install_root).unwrap_or(0);
            let spec_safe = sanitize_for_terminal(&entry.saved_spec);
            println!(
                "        spec: {}    installed: {}    size: {}",
                spec_safe.dimmed(),
                entry.installed_at.format("%Y-%m-%d").to_string().dimmed(),
                format_bytes(bytes).dimmed()
            );
            let root_safe = sanitize_for_terminal(&install_root.display().to_string());
            println!("        root: {}", root_safe.dimmed());
            if let Some(path) = linked_source_path(entry) {
                let path_safe = sanitize_for_terminal(path);
                println!("        linked: {}", path_safe.dimmed());
            }
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
            let alias_safe = sanitize_for_terminal(alias);
            let package_safe = sanitize_for_terminal(&entry.package);
            let bin_safe = sanitize_for_terminal(&entry.bin);
            println!(
                "    {} \u{2192} {}'s {}",
                alias_safe.bold(),
                package_safe,
                bin_safe.dimmed()
            );
        }
    }
    println!();
    install_ui::done(&format!(
        "{} global package{} installed",
        manifest.packages.len(),
        if manifest.packages.len() == 1 {
            ""
        } else {
            "s"
        }
    ));
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

fn run_bin(root: &LpmRoot, json_output: bool) {
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
    let display_path = display_path_for_entry(root, entry);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "package": package,
                "version": entry.resolved,
                "source": entry.source,
                "path": display_path,
            }))
            .unwrap()
        );
    } else {
        println!("{}", sanitize_for_terminal(&display_path));
    }
    Ok(())
}

// ─── link / unlink ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct LocalLinkBin {
    command_name: String,
    target: PathBuf,
}

#[derive(Debug, Clone)]
struct LocalLinkPackage {
    name: String,
    version: String,
    source_dir: PathBuf,
    root_relative: String,
    bins: Vec<LocalLinkBin>,
}

fn run_link(root: &LpmRoot, path: Option<&Path>, json_output: bool) -> Result<(), LpmError> {
    let link = load_local_link_package(path)?;
    let command_names: Vec<String> = link
        .bins
        .iter()
        .map(|bin| bin.command_name.clone())
        .collect();

    with_exclusive_lock(root.global_tx_lock(), || {
        let mut manifest = lpm_global::read_for(root)?;
        if let Some(existing) = manifest.packages.get(&link.name) {
            let name_safe = sanitize_for_terminal(&link.name);
            return match existing.source {
                PackageSource::LocalLink => Err(LpmError::Script(format!(
                    "'{name_safe}' is already linked globally. Run `lpm global unlink {name_safe}` \
                     before linking it again."
                ))),
                _ => Err(LpmError::Script(format!(
                    "'{name_safe}' is already globally installed from the registry. Run \
                     `lpm global remove {name_safe}` before linking a local checkout."
                ))),
            };
        }

        if let Some((other_name, _)) = manifest.packages.iter().find(|(other_name, entry)| {
            *other_name != &link.name && entry.root == link.root_relative
        }) {
            return Err(LpmError::Script(format!(
                "local-link root '{}' is already used by '{}'. Rename one package or unlink the \
                 existing package first.",
                sanitize_for_terminal(&link.root_relative),
                sanitize_for_terminal(other_name),
            )));
        }

        let collisions = find_command_collisions(&manifest, &link.name, &command_names);
        if !collisions.is_empty() {
            return Err(local_link_collision_error(&link.name, &collisions));
        }

        let result = materialize_local_link(root, &link).and_then(|()| {
            let entry = PackageEntry {
                saved_spec: format!("{LOCAL_LINK_SPEC_PREFIX}{}", link.source_dir.display()),
                resolved: link.version.clone(),
                integrity: "local-link".into(),
                source: PackageSource::LocalLink,
                installed_at: Utc::now(),
                root: link.root_relative.clone(),
                commands: command_names.clone(),
            };
            manifest.packages.insert(link.name.clone(), entry);
            lpm_global::write_for(root, &manifest)
        });

        if let Err(err) = result {
            cleanup_local_link_outputs(root, &link);
            return Err(err);
        }
        Ok(())
    })?;

    emit_link_success(&link, json_output);
    Ok(())
}

fn run_unlink(root: &LpmRoot, package: &str, json_output: bool) -> Result<(), LpmError> {
    let summary = with_exclusive_lock(root.global_tx_lock(), || {
        let mut manifest = lpm_global::read_for(root)?;
        let entry = manifest.packages.get(package).cloned().ok_or_else(|| {
            LpmError::Script(format!(
                "package '{}' is not globally linked. Run `lpm global list` to see installed packages.",
                sanitize_for_terminal(package),
            ))
        })?;
        if entry.source != PackageSource::LocalLink {
            return Err(LpmError::Script(format!(
                "'{}' is a registry-backed global install. Use `lpm global remove {}` to remove it.",
                sanitize_for_terminal(package),
                sanitize_for_terminal(package),
            )));
        }
        let _validated_root = validated_local_link_root(root, &entry.root)?;

        let aliases: Vec<(String, String)> = manifest
            .aliases
            .iter()
            .filter_map(|(alias, owner)| {
                (owner.package == package).then_some((alias.clone(), owner.bin.clone()))
            })
            .collect();
        for command in &entry.commands {
            remove_shim(&root.bin_dir(), command)?;
        }
        for (alias, _) in &aliases {
            remove_shim(&root.bin_dir(), alias)?;
        }
        if let Err(err) = remove_local_link_root(root, &entry.root) {
            if let Err(restore_failures) = restore_local_link_global_shims(root, &entry, &aliases) {
                return Err(LpmError::Script(format!(
                    "failed to remove local-link root for '{}': {err}. Additionally, failed to \
                     restore {} shim(s): {}",
                    sanitize_for_terminal(package),
                    restore_failures.len(),
                    restore_failures.join("; "),
                )));
            }
            return Err(err);
        }

        manifest.packages.remove(package);
        for (alias, _) in aliases {
            manifest.aliases.remove(&alias);
        }
        lpm_global::write_for(root, &manifest)?;

        let linked_path = linked_source_path(&entry).map(str::to_string);
        Ok(UnlinkSummary {
            package: package.to_string(),
            version: entry.resolved,
            linked_path,
            commands: entry.commands,
        })
    })?;

    emit_unlink_success(&summary, json_output);
    Ok(())
}

#[derive(Debug, Clone)]
struct UnlinkSummary {
    package: String,
    version: String,
    linked_path: Option<String>,
    commands: Vec<String>,
}

fn load_local_link_package(path: Option<&Path>) -> Result<LocalLinkPackage, LpmError> {
    let raw_dir = match path {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir().map_err(LpmError::Io)?,
    };
    let source_dir = raw_dir.canonicalize().map_err(|e| {
        LpmError::Script(format!(
            "could not resolve local package path '{}': {e}",
            sanitize_for_terminal(&raw_dir.display().to_string()),
        ))
    })?;
    if !source_dir.is_dir() {
        return Err(LpmError::Script(format!(
            "'{}' is not a directory",
            sanitize_for_terminal(&source_dir.display().to_string()),
        )));
    }

    let pkg_json = source_dir.join("package.json");
    let package = lpm_workspace::read_package_json(&pkg_json).map_err(|e| {
        LpmError::Script(format!(
            "failed to read local package manifest '{}': {e}",
            sanitize_for_terminal(&pkg_json.display().to_string()),
        ))
    })?;
    let name = package
        .name
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            LpmError::Script("local package.json must declare a non-empty `name`".into())
        })?;
    let version = package
        .version
        .filter(|version| !version.trim().is_empty())
        .ok_or_else(|| {
            LpmError::Script(format!(
                "local package '{}' must declare a non-empty `version`",
                sanitize_for_terminal(&name),
            ))
        })?;
    let Some(bin_config) = package.bin else {
        return Err(LpmError::Script(format!(
            "local package '{}' exposes no `bin` entries to link",
            sanitize_for_terminal(&name),
        )));
    };

    let mut entries = bin_config.entries(&name);
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries.dedup_by(|a, b| a.0 == b.0);
    if entries.is_empty() {
        return Err(LpmError::Script(format!(
            "local package '{}' exposes no non-empty `bin` entries to link",
            sanitize_for_terminal(&name),
        )));
    }

    let mut bins = Vec::with_capacity(entries.len());
    for (command_name, script_path) in entries {
        if let Err(err) = lpm_global::shim::validate_command_name(&command_name) {
            return Err(LpmError::Script(format!(
                "local package '{}' declares invalid bin command '{}': {err}",
                sanitize_for_terminal(&name),
                sanitize_for_terminal(&command_name),
            )));
        }
        let target = resolve_local_bin_target(&source_dir, &script_path)?;
        bins.push(LocalLinkBin {
            command_name,
            target,
        });
    }

    Ok(LocalLinkPackage {
        root_relative: local_link_root_relative(&name),
        name,
        version,
        source_dir,
        bins,
    })
}

fn resolve_local_bin_target(package_dir: &Path, script_path: &str) -> Result<PathBuf, LpmError> {
    let relative = normalize_relative_bin_path(script_path)?;
    let candidate = package_dir.join(&relative);
    let metadata = std::fs::metadata(&candidate).map_err(|e| {
        LpmError::Script(format!(
            "bin target '{}' does not exist or cannot be read: {e}",
            sanitize_for_terminal(&candidate.display().to_string()),
        ))
    })?;
    if !metadata.is_file() {
        return Err(LpmError::Script(format!(
            "bin target '{}' is not a file",
            sanitize_for_terminal(&candidate.display().to_string()),
        )));
    }
    let canonical = candidate.canonicalize().map_err(LpmError::Io)?;
    if !canonical.starts_with(package_dir) {
        return Err(LpmError::Script(format!(
            "bin target '{}' resolves outside the package directory",
            sanitize_for_terminal(&candidate.display().to_string()),
        )));
    }
    Ok(canonical)
}

fn normalize_relative_bin_path(script_path: &str) -> Result<PathBuf, LpmError> {
    if script_path.trim().is_empty() {
        return Err(LpmError::Script("bin target path must not be empty".into()));
    }
    let raw = Path::new(script_path);
    if raw.is_absolute() {
        return Err(LpmError::Script(format!(
            "bin target '{}' must be relative to the package root",
            sanitize_for_terminal(script_path),
        )));
    }
    let mut normalized = PathBuf::new();
    for component in raw.components() {
        match component {
            std::path::Component::Normal(part) => normalized.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(LpmError::Script(format!(
                    "bin target '{}' must not contain parent-directory traversal",
                    sanitize_for_terminal(script_path),
                )));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(LpmError::Script(format!(
                    "bin target '{}' must be relative to the package root",
                    sanitize_for_terminal(script_path),
                )));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(LpmError::Script("bin target path must not be empty".into()));
    }
    Ok(normalized)
}

fn local_link_root_relative(package_name: &str) -> String {
    let mut safe = String::with_capacity(package_name.len());
    for ch in package_name.chars() {
        match ch {
            '/' | '\\' => safe.push('+'),
            '@' | '.' | '_' | '-' | '+' => safe.push(ch),
            c if c.is_ascii_alphanumeric() => safe.push(c),
            _ => safe.push('_'),
        }
    }
    while safe.contains("..") {
        safe = safe.replace("..", "_");
    }
    if safe.is_empty() {
        safe.push_str("package");
    }
    format!("links/{safe}")
}

fn materialize_local_link(root: &LpmRoot, link: &LocalLinkPackage) -> Result<(), LpmError> {
    let link_root = validated_local_link_root(root, &link.root_relative)?;
    if std::fs::symlink_metadata(&link_root).is_ok() {
        remove_local_link_root(root, &link.root_relative)?;
    }
    let install_bin = link_root.join("node_modules").join(".bin");
    for bin in &link.bins {
        emit_shim(
            &install_bin,
            &Shim {
                command_name: bin.command_name.clone(),
                target: bin.target.clone(),
            },
        )?;
        if !artifacts_complete(&install_bin, &bin.command_name) {
            return Err(LpmError::Script(format!(
                "failed to create complete local-link shim for '{}'",
                sanitize_for_terminal(&bin.command_name),
            )));
        }
    }

    let global_bin = root.bin_dir();
    for bin in &link.bins {
        emit_shim(
            &global_bin,
            &Shim {
                command_name: bin.command_name.clone(),
                target: install_bin.join(&bin.command_name),
            },
        )?;
        if !artifacts_complete(&global_bin, &bin.command_name) {
            return Err(LpmError::Script(format!(
                "failed to create complete global shim for '{}'",
                sanitize_for_terminal(&bin.command_name),
            )));
        }
    }
    Ok(())
}

fn cleanup_local_link_outputs(root: &LpmRoot, link: &LocalLinkPackage) {
    for bin in &link.bins {
        let _ = remove_shim(&root.bin_dir(), &bin.command_name);
    }
    let _ = remove_local_link_root(root, &link.root_relative);
}

fn restore_local_link_global_shims(
    root: &LpmRoot,
    entry: &PackageEntry,
    aliases: &[(String, String)],
) -> Result<(), Vec<String>> {
    let install_bin = root
        .global_root()
        .join(&entry.root)
        .join("node_modules")
        .join(".bin");
    let mut failures = Vec::new();

    for command in &entry.commands {
        match emit_shim(
            &root.bin_dir(),
            &Shim {
                command_name: command.clone(),
                target: install_bin.join(command),
            },
        ) {
            Ok(_) if artifacts_complete(&root.bin_dir(), command) => {}
            Ok(_) => failures.push(format!(
                "{}: restored shim artifact is incomplete",
                sanitize_for_terminal(command)
            )),
            Err(err) => failures.push(format!("{}: {err}", sanitize_for_terminal(command))),
        }
    }

    for (alias, bin) in aliases {
        match emit_shim(
            &root.bin_dir(),
            &Shim {
                command_name: alias.clone(),
                target: install_bin.join(bin),
            },
        ) {
            Ok(_) if artifacts_complete(&root.bin_dir(), alias) => {}
            Ok(_) => failures.push(format!(
                "{}: restored alias shim artifact is incomplete",
                sanitize_for_terminal(alias)
            )),
            Err(err) => failures.push(format!("{}: {err}", sanitize_for_terminal(alias))),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

fn remove_local_link_root(root: &LpmRoot, relative: &str) -> Result<(), LpmError> {
    let path = validated_local_link_root(root, relative)?;
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_dir() => std::fs::remove_dir_all(&path)?,
        Ok(_) => std::fs::remove_file(&path)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(LpmError::Io(e)),
    }
    Ok(())
}

fn validated_local_link_root(root: &LpmRoot, relative: &str) -> Result<PathBuf, LpmError> {
    lpm_global::validated_local_link_root_relative(&root.global_root(), relative).map_err(
        |reason| {
            LpmError::Script(format!(
                "invalid local-link root '{}': {reason}",
                sanitize_for_terminal(relative),
            ))
        },
    )
}

fn local_link_collision_error(
    package: &str,
    collisions: &[lpm_global::CommandCollision],
) -> LpmError {
    let mut lines = Vec::with_capacity(collisions.len());
    for collision in collisions {
        let via = if collision.via_alias {
            "alias owned by"
        } else {
            "owned by"
        };
        lines.push(format!(
            "{} ({via} {})",
            sanitize_for_terminal(&collision.command),
            sanitize_for_terminal(&collision.current_owner),
        ));
    }
    LpmError::Script(format!(
        "local package '{}' cannot be linked because its command name{} already exist{}: {}. \
         Remove or unlink the owning package first.",
        sanitize_for_terminal(package),
        if collisions.len() == 1 { "" } else { "s" },
        if collisions.len() == 1 { "s" } else { "" },
        lines.join(", "),
    ))
}

fn emit_link_success(link: &LocalLinkPackage, json_output: bool) {
    let commands: Vec<String> = link
        .bins
        .iter()
        .map(|bin| bin.command_name.clone())
        .collect();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "package": link.name,
                "version": link.version,
                "path": link.source_dir.display().to_string(),
                "commands": commands,
            }))
            .unwrap()
        );
        return;
    }
    install_ui::done(&format!(
        "Linked {}@{}",
        sanitize_for_terminal(&link.name),
        sanitize_for_terminal(&link.version),
    ));
    install_ui::phase(&format!(
        "Path: {}",
        sanitize_for_terminal(&link.source_dir.display().to_string()).dimmed(),
    ));
    install_ui::phase(&format!("Commands: {}", format_bins(&commands).dimmed(),));
}

fn emit_unlink_success(summary: &UnlinkSummary, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "package": summary.package,
                "version": summary.version,
                "path": summary.linked_path,
                "commands": summary.commands,
            }))
            .unwrap()
        );
        return;
    }
    install_ui::done(&format!(
        "Unlinked {}@{}",
        sanitize_for_terminal(&summary.package),
        sanitize_for_terminal(&summary.version),
    ));
}

fn linked_source_path(entry: &PackageEntry) -> Option<&str> {
    (entry.source == PackageSource::LocalLink)
        .then(|| entry.saved_spec.strip_prefix(LOCAL_LINK_SPEC_PREFIX))
        .flatten()
}

fn display_path_for_entry(root: &LpmRoot, entry: &PackageEntry) -> String {
    linked_source_path(entry).map_or_else(
        || root.global_root().join(&entry.root).display().to_string(),
        str::to_string,
    )
}

// ─── helpers ───────────────────────────────────────────────────────────

/// Best-effort post-commit tombstone sweep. Never fails
/// the caller and never surfaces visible output unless actual cleanup
/// happened — a janitor, not a progress report.
///
/// Shared across every user-facing global mutator (`install -g`,
/// `uninstall -g`, `global update`). Using the non-blocking
/// `try_sweep_tombstones` means parallel global commands don't stack up
/// waiting on each other's sweeps — whichever one grabs the tx lock
/// next will pick up the leftovers. `skipped_locked` is intentionally
/// not logged because under contention the NEXT command's sweep will
/// handle it and an unobservable miss isn't a problem worth narrating.
pub(crate) fn run_opportunistic_sweep(root: &LpmRoot) {
    match lpm_global::try_sweep_tombstones(root) {
        Ok(report) => {
            if !report.swept.is_empty() {
                tracing::debug!(
                    "opportunistic sweep: removed {} tombstone(s), freed {} bytes",
                    report.swept.len(),
                    report.freed_bytes
                );
            }
            for failure in &report.retained {
                tracing::debug!(
                    "opportunistic sweep: retained {} ({})",
                    failure.relative_path,
                    failure.reason
                );
            }
        }
        Err(e) => {
            tracing::debug!("opportunistic sweep failed (non-fatal): {e}");
        }
    }
}

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

    fn scoped_lpm_home(path: &std::path::Path) -> crate::test_env::ScopedEnv {
        crate::test_env::ScopedEnv::set([("LPM_HOME", path.as_os_str().to_owned())])
    }

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
        let _env = scoped_lpm_home(tmp.path());
        let r = run(
            &lpm_registry::RegistryClient::new(),
            GlobalCmd::List {
                outdated: false,
                verbose: false,
            },
            true,
        )
        .await;
        assert!(r.is_ok());
    }

    /// `--outdated` on an empty manifest prints an
    /// "all up-to-date" (or "no globals") result and short-circuits
    /// before any registry call.
    #[tokio::test]
    async fn list_outdated_empty_manifest_returns_ok() {
        let tmp = TempDir::new().unwrap();
        let _env = scoped_lpm_home(tmp.path());
        let r = run(
            &lpm_registry::RegistryClient::new(),
            GlobalCmd::List {
                outdated: true,
                verbose: false,
            },
            true,
        )
        .await;
        // Empty manifest short-circuits before any registry call, so
        // this is the only --outdated test that doesn't need network
        // mocking. Full batch-metadata integration tests are in the
        // outdated-specific tests below (pure helpers like
        // `pick_latest_matching`) — the end-to-end network path is
        // exercised by smoke test, not unit test.
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn list_emits_seeded_packages() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed(&root);

        let _env = scoped_lpm_home(tmp.path());
        let r = run(
            &lpm_registry::RegistryClient::new(),
            GlobalCmd::List {
                outdated: false,
                verbose: true,
            },
            true,
        )
        .await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn bin_prints_bin_dir() {
        let tmp = TempDir::new().unwrap();
        let _env = scoped_lpm_home(tmp.path());
        let r = run(&lpm_registry::RegistryClient::new(), GlobalCmd::Bin, true).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn path_succeeds_for_known_package() {
        let tmp = TempDir::new().unwrap();
        let root = LpmRoot::from_dir(tmp.path());
        seed(&root);

        let _env = scoped_lpm_home(tmp.path());
        let r = run(
            &lpm_registry::RegistryClient::new(),
            GlobalCmd::Path {
                package: "eslint".into(),
            },
            true,
        )
        .await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn path_errors_for_unknown_package() {
        let tmp = TempDir::new().unwrap();
        let _env = scoped_lpm_home(tmp.path());
        let r = run(
            &lpm_registry::RegistryClient::new(),
            GlobalCmd::Path {
                package: "does-not-exist".into(),
            },
            true,
        )
        .await;
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

    // ─── pick_latest_matching ──────────────────────────────────

    use lpm_registry::PackageMetadata;

    /// Build a minimal `PackageMetadata` with the given version keys.
    /// Dist tags optional.
    fn fake_metadata(name: &str, versions: &[&str], dist_tags: &[(&str, &str)]) -> PackageMetadata {
        // PackageMetadata serde accepts a relatively narrow shape; build
        // it via JSON round-trip so this test stays decoupled from any
        // private fields the struct might have.
        let versions_json: serde_json::Value = versions
            .iter()
            .map(|v| {
                (
                    v.to_string(),
                    serde_json::json!({"name": name, "version": v}),
                )
            })
            .collect::<std::collections::HashMap<_, _>>()
            .into_iter()
            .collect();
        let dist_tags_json: serde_json::Value = dist_tags
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::json!(v)))
            .collect::<std::collections::HashMap<_, _>>()
            .into_iter()
            .collect();
        let body = serde_json::json!({
            "name": name,
            "versions": versions_json,
            "dist-tags": dist_tags_json,
        });
        serde_json::from_value(body).expect("PackageMetadata shape")
    }

    #[test]
    fn pick_latest_matching_dist_tag_resolves() {
        let meta = fake_metadata(
            "eslint",
            &["9.23.0", "9.24.0", "9.25.0-beta"],
            &[("latest", "9.24.0"), ("next", "9.25.0-beta")],
        );
        assert_eq!(pick_latest_matching(&meta, "latest").unwrap(), "9.24.0");
        assert_eq!(pick_latest_matching(&meta, "next").unwrap(), "9.25.0-beta");
    }

    #[test]
    fn pick_latest_matching_exact_version_present_in_registry_passes_through() {
        let meta = fake_metadata("eslint", &["9.23.0", "9.24.0"], &[]);
        assert_eq!(pick_latest_matching(&meta, "9.24.0").unwrap(), "9.24.0");
    }

    /// An exact pin the registry no longer serves must surface as `unresolved`.
    #[test]
    fn pick_latest_matching_exact_version_missing_from_registry_surfaces_as_unresolved() {
        let meta = fake_metadata("eslint", &["9.23.0", "9.24.0"], &[]);
        let err = pick_latest_matching(&meta, "100.0.0").unwrap_err();
        assert!(
            err.contains("registry no longer serves"),
            "missing exact pin must surface a 'no longer served' message; got: {err}"
        );
        assert!(
            err.contains("100.0.0"),
            "error must name the missing version; got: {err}"
        );
    }

    #[test]
    fn pick_latest_matching_range_picks_max_satisfying() {
        let meta = fake_metadata("eslint", &["8.99.0", "9.23.0", "9.24.0", "10.0.0"], &[]);
        assert_eq!(pick_latest_matching(&meta, "^9").unwrap(), "9.24.0");
        assert_eq!(pick_latest_matching(&meta, "~9.23.0").unwrap(), "9.23.0");
    }

    #[test]
    fn pick_latest_matching_wildcard_picks_highest_overall() {
        let meta = fake_metadata("eslint", &["8.99.0", "9.24.0"], &[]);
        assert_eq!(pick_latest_matching(&meta, "*").unwrap(), "9.24.0");
    }

    #[test]
    fn pick_latest_matching_unparseable_spec_errors() {
        let meta = fake_metadata("eslint", &["9.24.0"], &[]);
        let err = pick_latest_matching(&meta, "not-a-version").unwrap_err();
        assert!(err.contains("not a valid range"));
    }

    #[test]
    fn pick_latest_matching_range_with_no_satisfying_version_errors() {
        let meta = fake_metadata("eslint", &["8.0.0", "8.1.0"], &[]);
        let err = pick_latest_matching(&meta, "^9").unwrap_err();
        assert!(err.contains("no version"));
    }

    /// Manifest-controlled package / alias / version / saved-spec / install
    /// root strings are passed through `sanitize_for_terminal` before any
    /// styling reaches the terminal — a hostile registry or corrupted
    /// manifest can no longer emit OSC 8 hyperlinks, OSC 52 clipboard
    /// writes, CSI cursor manipulation, or BEL/DEL through `lpm global
    /// list` / `lpm global path` / `lpm global list --outdated`.
    #[test]
    fn sanitize_for_terminal_strips_osc_and_bel_from_global_field_payload() {
        let osc8 = "\u{1b}]8;;file:///etc/passwd\u{07}evil-pkg\u{1b}]8;;\u{07}";
        let cleaned = sanitize_for_terminal(osc8);
        assert!(!cleaned.contains('\u{1b}'));
        assert!(!cleaned.contains('\u{07}'));
        assert!(cleaned.contains("evil-pkg"));

        let osc52 = "pkg\u{1b}]52;c;YmFkLXBheWxvYWQ=\u{07}";
        let cleaned = sanitize_for_terminal(osc52);
        assert!(!cleaned.contains('\u{1b}'));
        assert!(!cleaned.contains('\u{07}'));
        assert!(cleaned.starts_with("pkg"));

        let csi = "1.0.0\u{1b}[2J\u{1b}[H";
        let cleaned = sanitize_for_terminal(csi);
        assert!(!cleaned.contains('\u{1b}'));
        assert!(cleaned.contains("1.0.0"));
    }
}
