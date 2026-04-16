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
        /// and flag packages with newer versions available under the
        /// persisted `saved_spec`. Uses batch metadata so large global
        /// manifests can be checked without one registry round-trip per
        /// package.
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

    /// Remove a globally-installed package.
    ///
    /// Equivalent to `lpm uninstall -g <pkg>` — both invocations route
    /// through the same M3.3 implementation.
    Remove {
        /// Package name (e.g. `eslint`, `@lpm.dev/owner.tool`).
        package: String,
    },

    /// Update a globally-installed package (or all of them).
    ///
    /// With no argument: re-resolve every globally-installed package
    /// against its persisted `saved_spec` and upgrade any that have
    /// a newer matching version available. Phase 33 precedence applies
    /// — preserved ranges, dist-tag re-pin, etc.
    ///
    /// With `<pkg>` (no version): same flow scoped to one package.
    ///
    /// With `<pkg>@<spec>` (M3.4 stretch): rewrite the saved_spec
    /// using Phase 33's `decide_saved_dependency_spec`, then upgrade.
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
            run_list(&root, &manifest, outdated, verbose, json_output)
        }
        GlobalCmd::Bin => run_bin(&root, json_output),
        GlobalCmd::Path { package } => run_path(&root, &manifest, &package, json_output),
        // `lpm global remove` and `lpm uninstall -g` are two surfaces
        // for the same operation. Both route through the M3.3
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
) -> Result<(), LpmError> {
    // `outdated == true` is routed through `run_list_outdated` in the
    // dispatch match — this function only sees the non-outdated path.
    if json_output {
        emit_list_json(root, manifest, verbose);
    } else {
        emit_list_human(root, manifest, verbose);
    }
    Ok(())
}

// ─── M6.1: lpm global list --outdated ─────────────────────────────────

/// Phase 37 M6.1: compare each globally-installed package's resolved
/// version against the highest version the registry exposes under the
/// package's persisted `saved_spec`. Report packages whose registry
/// has something newer.
///
/// Optimization: uses `RegistryClient::batch_metadata` so the whole
/// manifest fits in 1-3 HTTP round-trips regardless of how many
/// packages are globally installed. Individual `get_package_metadata`
/// calls per package would be N round-trips; the batch endpoint is
/// the right shape for the "list everything outdated" query.
///
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
                }))
                .unwrap()
            );
        } else {
            output::info("No globally-installed packages.");
        }
        return Ok(());
    }

    // Single batch call covers every globally-installed package.
    // Phase 35 Step 6 fix: use the injected client (carries
    // `--registry` + SessionManager). The local `build_registry()`
    // helper is now unused.
    let names: Vec<String> = manifest.packages.keys().cloned().collect();
    let metadata = match client.batch_metadata(&names).await {
        Ok(m) => m,
        Err(e) => {
            return Err(LpmError::Script(format!(
                "batch metadata fetch failed — cannot compute outdated: {e}"
            )));
        }
    };

    let mut outdated: Vec<OutdatedRow> = Vec::new();
    let mut up_to_date: Vec<String> = Vec::new();
    let mut unresolved: Vec<UnresolvedRow> = Vec::new();

    for (name, entry) in &manifest.packages {
        let Some(meta) = metadata.get(name) else {
            unresolved.push(UnresolvedRow {
                package: name.clone(),
                reason: "no registry metadata returned for this package".into(),
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
            outdated.push(OutdatedRow {
                package: name.clone(),
                current: entry.resolved.clone(),
                latest,
                saved_spec: entry.saved_spec.clone(),
            });
        }
    }
    outdated.sort_by(|a, b| a.package.cmp(&b.package));
    up_to_date.sort();
    unresolved.sort_by(|a, b| a.package.cmp(&b.package));

    if json_output {
        emit_outdated_json(&outdated, &up_to_date, &unresolved);
    } else {
        emit_outdated_human(&outdated, &up_to_date, &unresolved, verbose);
    }
    Ok(())
}

/// One row in the `--outdated` report where the registry has a newer
/// version that satisfies the persisted `saved_spec`.
#[derive(Debug, Clone)]
struct OutdatedRow {
    package: String,
    current: String,
    latest: String,
    saved_spec: String,
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
/// inlined here to keep M6.1 independent of M3.4's internals.
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
    // Exact version: accept it verbatim if the registry still has it.
    if lpm_semver::Version::parse(saved_spec).is_ok() {
        return Ok(saved_spec.to_string());
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

// Phase 35 Step 6 fix: removed `build_registry` — all callers now
// receive the injected `&RegistryClient` from `main.rs` so the
// `--registry` flag and the shared `SessionManager` are honored.

fn emit_outdated_json(
    outdated: &[OutdatedRow],
    up_to_date: &[String],
    unresolved: &[UnresolvedRow],
) {
    let out_entries: Vec<_> = outdated
        .iter()
        .map(|r| {
            serde_json::json!({
                "package": r.package,
                "current": r.current,
                "latest": r.latest,
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
            "success": true,
            "count_outdated": outdated.len(),
            "outdated": out_entries,
            "up_to_date": up_to_date,
            "unresolved": unresolved_entries,
        }))
        .unwrap()
    );
}

fn emit_outdated_human(
    outdated: &[OutdatedRow],
    up_to_date: &[String],
    unresolved: &[UnresolvedRow],
    verbose: bool,
) {
    if outdated.is_empty() && unresolved.is_empty() {
        output::success(&format!(
            "All {} globally-installed package{} are up-to-date.",
            up_to_date.len(),
            if up_to_date.len() == 1 { "" } else { "s" },
        ));
        return;
    }

    if !outdated.is_empty() {
        println!();
        println!("  {} outdated:", outdated.len().to_string().bold(),);
        for r in outdated {
            println!(
                "    {} {} \u{2192} {}{}",
                r.package.bold(),
                r.current.dimmed(),
                r.latest.green(),
                if verbose {
                    format!("  (spec: {})", r.saved_spec.dimmed())
                } else {
                    String::new()
                },
            );
        }
        println!();
        output::info(
            "Run `lpm global update <pkg>` to upgrade one, or \
             `lpm global update` to upgrade every outdated install.",
        );
        println!();
    }
    if !unresolved.is_empty() {
        output::warn(&format!(
            "{} package{} could not be compared:",
            unresolved.len(),
            if unresolved.len() == 1 { "" } else { "s" },
        ));
        for r in unresolved {
            println!("    {}: {}", r.package.bold(), r.reason.dimmed());
        }
        println!();
    }
    if !up_to_date.is_empty() && verbose {
        output::info(&format!(
            "{} up-to-date: {}",
            up_to_date.len(),
            up_to_date.join(", ").dimmed(),
        ));
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

/// Best-effort post-commit tombstone sweep (Phase 37 M3.5). Never fails
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

    /// Phase 37 M6.1: `--outdated` on an empty manifest prints an
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

    // ─── M6.1: pick_latest_matching ──────────────────────────────────

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
    fn pick_latest_matching_exact_version_passes_through() {
        let meta = fake_metadata("eslint", &["9.23.0", "9.24.0"], &[]);
        // Exact that matches the registry.
        assert_eq!(pick_latest_matching(&meta, "9.24.0").unwrap(), "9.24.0");
        // Exact we've never heard of is STILL accepted at the
        // "saved_spec resolved to exact" level. The caller compares
        // against entry.resolved; a registry-missing exact shows as
        // up-to-date (no upgrade target). Matches project install.
        assert_eq!(pick_latest_matching(&meta, "100.0.0").unwrap(), "100.0.0");
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
}
