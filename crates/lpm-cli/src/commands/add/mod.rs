mod conflict;
mod dependencies;
mod display;
mod paths;
mod project;
mod security;
mod source;
mod swift;
mod target;

pub use security::print_security_warnings;

use crate::commands::install::{
    NpmFirewallMaterializationPackage, prepare_npm_firewall_materialization_preflight,
    registry_materialization_route_is_public_npm,
    run_prepared_npm_firewall_materialization_preflight,
};
use crate::prompt::prompt_err;
use crate::{install_ui, output};
use conflict::{ConflictAction, handle_file_conflict};
use dependencies::{
    count_dependencies, handle_dependencies, pm_lockfile_paths, preflight_no_manifest_with_deps,
};
use display::{
    dependencies_word, files_word, handle_dry_run, print_add_file, print_add_project_structure,
};
use lpm_common::LpmError;
use lpm_registry::{RegistryClient, RouteTable};
use paths::{prepare_safe_dest_parent, resolve_safe_dest_validate, validate_extracted_paths};
use project::{
    detect_buyer_alias, detect_default_install_dir, detect_package_manager, resolve_target_dir,
};
use source::{
    collect_source_with_fallback, filter_config_files, is_runtime_source_text_file,
    json_value_to_config_string, read_lpm_config,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use swift::handle_swift_lpm_deps;
use target::{AddTarget, resolve_add_target};

/// Add source files from a package into your project (shadcn-style).
///
/// Always does source delivery: download, extract, copy files.
/// For managed dependency installation, use `lpm install` instead.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    package_spec: &str,
    target_path: Option<&str>,
    yes: bool,
    json_output: bool,
    force: bool,
    dry_run: bool,
    no_install_deps: bool,
    no_skills: bool,
    no_editor_setup: bool,
    no_engine_strict: bool,
    pm: &str,
    alias_override: Option<&str>,
    swift_target: Option<&str>,
) -> Result<(), LpmError> {
    let add_started = std::time::Instant::now();
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let reviewed = crate::typosquat_guard::guard_explicit_package_specs(
        project_dir,
        &[package_spec.to_string()],
        &[project_dir.to_path_buf()],
        yes,
        json_output,
    )?;
    let package_spec =
        reviewed.specs.first().map(String::as_str).ok_or_else(|| {
            LpmError::Registry("internal typosquat guard returned no package".into())
        })?;

    // Resolve package reference into AddTarget.
    // `@lpm.dev/owner.name` → AddTarget::Lpm(PackageName); everything else
    // → AddTarget::Npm { spec } verbatim. No dotted-name auto-prepend.
    let (target, version_spec, mut inline_config) = resolve_add_target(package_spec)?;

    // `.npmrc` setup before any network call.
    //
    // Build the RouteTable BEFORE any network call so:
    // - fatal `${MISSING_VAR}` errors abort early (npm parity);
    // - advisory warnings surface in non-JSON mode;
    // - the `strict-ssl=false` security warning escapes `--json` (stderr);
    // - TLS overrides (`cafile=`, `strict-ssl=false`) take effect on the
    //   metadata + tarball fetches via `with_tls_overrides`.
    let route_table = RouteTable::from_env_and_filesystem(project_dir)
        .map_err(|e| LpmError::Registry(format!("npmrc: {e}")))?;
    if !json_output {
        for w in route_table.npmrc_warnings() {
            output::warn(&lpm_common::sanitize_terminal_inline(w));
        }
    }
    // strict-ssl=false is a security signal; emit unconditionally on stderr.
    if let Some(tagged) = route_table.tls_overrides().strict_ssl.as_ref()
        && !tagged.value
    {
        output::warn(&format!(
            "strict-ssl=false in {}:{} — TLS certificate verification is \
             DISABLED for this `lpm add` across ALL registries. This is a \
             security risk.",
            lpm_common::sanitize_terminal_inline(&tagged.source),
            tagged.line
        ));
    }
    // Project-local `.npmrc` refusals are surfaced even in JSON mode.
    for w in route_table.npmrc_security_warnings() {
        output::warn(&lpm_common::sanitize_terminal_inline(w));
    }
    // Request-aware eager-build: `lpm add <spec>`'s
    // top-level request is exactly `{spec}`. The fetch site below
    // (`get_npm_metadata_routed(spec, …)`) and version resolution
    // (`resolve_version_spec(version_spec)`) both operate on the
    // raw `target` and `version_spec` strings — npm aliases like
    // `lpm add foo@npm:react@18` are NOT currently supported by
    // those paths (they'd route + fetch as `foo`, not `react`). So
    // the eager-set inputs mirror actual fetch behavior: the local
    // target name, no alias unwrapping. If alias support lands for
    // `lpm add` later, the alias-target unwrap should be applied
    // here AND in the fetch + resolve paths in lockstep.
    let top_level_specs: Vec<String> = vec![target.display()];
    let eager_origins = route_table.effective_registry_origins(
        &top_level_specs,
        client.base_url(),
        client.npm_registry_url(),
    );
    let owned_client = client
        .clone_with_config()
        .with_tls_overrides_for(route_table.tls_overrides(), &eager_origins)?;
    let client = &owned_client;
    // Install-start summary of effective TLS overrides.
    if !json_output && let Some(line) = client.render_effective_tls_summary() {
        output::info(&lpm_common::sanitize_terminal_inline(&line));
    }

    // Routed metadata fetch.
    // - AddTarget::Lpm → lpm.dev metadata API (LpmWorker route, forced
    //   by `@lpm.dev/` prefix in `RouteTable::route_for_package`).
    // - AddTarget::Npm → routed npm metadata via .npmrc / NpmDirect /
    //   LpmWorker per the route table.
    let metadata = match &target {
        AddTarget::Lpm(pkg) => client.get_package_metadata(pkg).await?,
        AddTarget::Npm { spec } => {
            let route = route_table.route_for_package(spec);
            client.get_npm_metadata_routed(spec, route).await?
        }
    };

    // Version-spec resolution covers dist-tags + semver ranges
    // such as `react@beta` and `lodash@^4`.
    let version = if let Some(v) = &version_spec {
        metadata.resolve_version_spec(v)?
    } else {
        metadata
            .latest_version_tag()
            .ok_or_else(|| LpmError::NotFound("no latest version".into()))?
            .to_string()
    };

    let ver_meta = metadata
        .version(&version)
        .ok_or_else(|| LpmError::NotFound(format!("version {version} not found")))?;
    let integrity = ver_meta.integrity_or_shasum();
    let target_route_name = target.route_name();
    let firewall_packages = match &target {
        AddTarget::Npm { .. }
            if registry_materialization_route_is_public_npm(
                &route_table,
                client,
                &target_route_name,
            ) =>
        {
            vec![NpmFirewallMaterializationPackage::new(
                &metadata.name,
                &version,
                integrity.as_deref(),
                metadata.time.get(&version).map(String::as_str),
            )]
        }
        AddTarget::Npm { .. } | AddTarget::Lpm(_) => Vec::new(),
    };
    let firewall_preflight = prepare_npm_firewall_materialization_preflight(
        project_dir,
        &firewall_packages,
        json_output,
    )?;

    if !json_output {
        let download_message = install_ui::TerminalLine::new("Downloading source package ")
            .yellow(&format!("{}@{version}", target.display()));
        install_ui::phase_line(install_ui::with_firewall_badge(
            download_message,
            firewall_preflight.is_active(),
        ));
    }

    let firewall_json = run_prepared_npm_firewall_materialization_preflight(
        client,
        firewall_preflight,
        json_output,
    )
    .await?;

    // File-spool tarball download.
    // Uses `download_tarball_routed` so:
    //   - LpmWorker / NpmDirect → no-auth file-spool;
    //   - Custom (`.npmrc`-declared private registry) → auth-attached
    //     file-spool, no LPM session bearer leak to the custom origin.
    // File-spool gives bounded memory (`MAX_COMPRESSED_TARBALL_SIZE`,
    // 500 MB) for free — `lpm add typescript` (~22 MB) and the worst-
    // case `lpm add @scope/giant-fixture` no longer load the full
    // tarball into RAM.
    let tarball_url = ver_meta
        .tarball_url()
        .ok_or_else(|| LpmError::NotFound("no tarball URL".into()))?;
    let downloaded = client
        .download_tarball_routed(&route_table, &target.route_name(), tarball_url)
        .await?;

    // Verify integrity. Fast path: SRI compare against the
    // SHA-512 hash already computed during download. Slow path: stream-
    // verify from the temp file (covers non-sha512 expected values).
    // Mirrors install.rs:8156-8170.
    if let Some(integrity) = integrity {
        let integrity = integrity.as_ref();
        if downloaded.sri != integrity
            && let Err(e) = lpm_extractor::verify_integrity_file(downloaded.file.path(), integrity)
        {
            return Err(LpmError::Registry(format!(
                "integrity verification failed for {}@{}: {e}",
                target.display(),
                version
            )));
        }
    } else {
        tracing::debug!(
            "no integrity hash for {}@{}, skipping verification",
            target.display(),
            version
        );
    }

    // Extract tarball from the spooled file (bounded-memory
    // path).
    let temp_dir = tempfile::tempdir().map_err(LpmError::Io)?;
    let extracted_paths =
        lpm_extractor::extract_tarball_from_file(downloaded.file.path(), temp_dir.path())?;

    // Validate extracted paths for path traversal. The user-side
    // write-time containment check happens before copying files.
    validate_extracted_paths(&extracted_paths, temp_dir.path())?;

    // Read lpm.config.json.
    let lpm_config = read_lpm_config(temp_dir.path())?;

    // Non-interactive simple-path guard.
    //
    // The simple path (no `lpm.config.json`) is a download-manager flow:
    // copy source files into a user-chosen directory, no auto-deps. In
    // interactive mode the user gets a prompt for the target dir. In
    // non-interactive mode (`--yes`, `--json`, or non-TTY) without
    // `--path`, defaulting silently into a heuristic-detected
    // `components/` is a CI/automation footgun — the user has no chance
    // to confirm where 3rd-party source landed. Refuse explicitly.
    //
    // Swift packages still hit this branch via the rich-config check
    // below (every Swift package on lpm.dev has a `lpm.config.json`),
    // so the Swift auto-default at `resolve_target_dir` is unaffected.
    let is_non_interactive = yes || json_output || !is_tty;
    if lpm_config.is_none() && target_path.is_none() && is_non_interactive {
        return Err(LpmError::Registry(
            "non-interactive mode (--yes, --json, or non-TTY) requires --path \
             for packages without lpm.config.json: cannot safely default a \
             target directory for arbitrary source copy"
                .into(),
        ));
    }

    // Config schema interactive prompts.
    if let Some(config) = &lpm_config
        && let Some(schema) = config.get("configSchema").and_then(|s| s.as_object())
    {
        if !yes && !json_output && is_tty {
            for (key, field) in schema {
                // Skip if already provided via inline config
                if inline_config.contains_key(key) {
                    continue;
                }

                let field_type = field
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("string");
                let label = field.get("label").and_then(|l| l.as_str()).unwrap_or(key);
                let default_val = config
                    .get("defaultConfig")
                    .and_then(|dc| dc.get(key))
                    .and_then(json_value_to_config_string)
                    .or_else(|| field.get("default").and_then(json_value_to_config_string))
                    .unwrap_or_default();
                let safe_label = crate::prompt::untrusted(label);

                match field_type {
                    "boolean" => {
                        let result = cliclack::confirm(safe_label)
                            .initial_value(default_val == "true")
                            .interact()
                            .map_err(prompt_err)?;
                        inline_config.insert(key.clone(), result.to_string());
                    }
                    "select" => {
                        let multi = field
                            .get("multiSelect")
                            .and_then(|m| m.as_bool())
                            .unwrap_or(false);
                        // Parse options as (value, label) pairs
                        let options: Vec<(String, String)> = field
                            .get("options")
                            .and_then(|o| o.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| {
                                        if let Some(s) = v.as_str() {
                                            Some((s.to_string(), s.to_string()))
                                        } else {
                                            let value =
                                                v.get("value").and_then(|vv| vv.as_str())?;
                                            let label_str = v
                                                .get("label")
                                                .and_then(|l| l.as_str())
                                                .unwrap_or(value);
                                            Some((value.to_string(), label_str.to_string()))
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();

                        if options.is_empty() {
                            continue;
                        }

                        let values: Vec<String> = options.iter().map(|(v, _)| v.clone()).collect();

                        if multi {
                            let mut ms = cliclack::multiselect(safe_label);
                            for (value, label_str) in &options {
                                ms =
                                    ms.item(value.clone(), crate::prompt::untrusted(label_str), "");
                            }
                            // Default all selected
                            ms = ms.initial_values(values);
                            let selected_values: Vec<String> = ms.interact().map_err(prompt_err)?;
                            let selected: Vec<&str> =
                                selected_values.iter().map(|s| s.as_str()).collect();
                            inline_config.insert(key.clone(), selected.join(","));
                        } else {
                            let default_idx = values
                                .iter()
                                .position(|v| *v == default_val.as_str())
                                .unwrap_or(0);
                            let mut sel = cliclack::select(safe_label);
                            for (i, (value, label_str)) in options.iter().enumerate() {
                                sel = sel.item(
                                    value.clone(),
                                    crate::prompt::untrusted(label_str),
                                    "",
                                );
                                if i == default_idx {
                                    sel = sel.initial_value(value.clone());
                                }
                            }
                            let chosen: String = sel.interact().map_err(prompt_err)?;
                            inline_config.insert(key.clone(), chosen);
                        }
                    }
                    _ => {
                        // string / text input
                        let value: String = cliclack::input(safe_label)
                            .default_input(&crate::prompt::untrusted(&default_val))
                            .interact()
                            .map_err(prompt_err)?;
                        inline_config.insert(key.clone(), value);
                    }
                }
            }
        } else if yes {
            // --yes: use defaults for required fields that aren't provided
            for (key, field) in schema {
                if inline_config.contains_key(key) {
                    continue;
                }
                let is_required = field
                    .get("required")
                    .and_then(|r| r.as_bool())
                    .unwrap_or(false);
                if is_required {
                    let default_val = config
                        .get("defaultConfig")
                        .and_then(|dc| dc.get(key))
                        .and_then(json_value_to_config_string)
                        .or_else(|| field.get("default").and_then(json_value_to_config_string))
                        .unwrap_or_default();
                    inline_config.insert(key.clone(), default_val);
                }
            }
        }
    }

    // Detect ecosystem and determine target.
    let ecosystem = lpm_config
        .as_ref()
        .and_then(|c| c.get("ecosystem").and_then(|v| v.as_str()))
        .unwrap_or("js");

    // Interactive target directory selection.
    let target_dir = if target_path.is_some() {
        resolve_target_dir(project_dir, target_path, ecosystem, swift_target)
    } else if !yes && !json_output && is_tty && ecosystem != "swift" {
        let default_dir = detect_default_install_dir(project_dir, ecosystem);
        let default_str = default_dir
            .strip_prefix(project_dir)
            .unwrap_or(&default_dir)
            .display()
            .to_string();

        let target: String = cliclack::input("Install directory")
            .default_input(&default_str)
            .placeholder(&default_str)
            .interact()
            .map_err(prompt_err)?;

        project_dir.join(target)
    } else {
        resolve_target_dir(project_dir, target_path, ecosystem, swift_target)
    };

    // Build file list (config-based, lpm.source fallback, or all files).
    let files = if let Some(config) = &lpm_config {
        if let Some(files_arr) = config.get("files").and_then(|f| f.as_array()) {
            filter_config_files(temp_dir.path(), files_arr, &inline_config)
        } else {
            collect_source_with_fallback(temp_dir.path())?
        }
    } else {
        collect_source_with_fallback(temp_dir.path())?
    };

    if files.is_empty() {
        return Err(LpmError::Registry("no files to install".into()));
    }

    // Dry-run mode: show what would happen and exit.
    if dry_run {
        return handle_dry_run(
            project_dir,
            &target_dir,
            &files,
            force,
            &target,
            &version,
            &lpm_config,
            &inline_config,
            ecosystem,
            temp_dir.path(),
            json_output,
        );
    }

    // Refuse to copy a deps-declaring source package into a project
    // with no `package.json`.
    //
    // Without a manifest, the dep entries the source declares have
    // nowhere to land; the user would end up with copied source
    // files importing packages they can't install. Hard-error here,
    // BEFORE any user-side side effects (prompts, file copies, dep
    // install). The remediation hint points
    // at `lpm init` / `npm init -y` so the user knows the fix; the
    // `--no-install-deps` escape preserves the existing "I'll
    // handle deps myself" path.
    preflight_no_manifest_with_deps(
        project_dir,
        temp_dir.path(),
        &lpm_config,
        &inline_config,
        no_install_deps,
    )?;

    // Prepare import rewriting.
    let author_alias = lpm_config
        .as_ref()
        .and_then(|c| c.get("importAlias"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Detect buyer alias from tsconfig/jsconfig, then prompt to confirm.
    // --alias flag overrides all detection and prompting.
    let buyer_alias = if ecosystem == "swift" {
        // Swift uses `import ModuleName`, not path aliases
        None
    } else if let Some(explicit) = alias_override {
        // --alias flag takes precedence
        let alias = if explicit.ends_with('/') {
            explicit.to_string()
        } else {
            format!("{explicit}/")
        };
        Some(alias)
    } else {
        let detected = detect_buyer_alias(project_dir);

        if !yes && !json_output && is_tty {
            // Build a sensible default: detected alias + target relative path
            let target_rel = target_dir
                .strip_prefix(project_dir)
                .unwrap_or(&target_dir)
                .to_string_lossy()
                .to_string();
            let default_alias = if let Some(ref alias) = detected {
                format!("{}{}", alias, target_rel)
            } else if !target_rel.is_empty() {
                format!("@/{}", target_rel)
            } else {
                String::new()
            };

            let input: String = cliclack::input(
                "Import alias for this directory? (leave empty for relative imports)",
            )
            .default_input(&default_alias)
            .placeholder(&default_alias)
            .required(false)
            .interact()
            .map_err(prompt_err)?;

            let trimmed = input.trim();
            if trimmed.is_empty() {
                None
            } else {
                let alias = if trimmed.ends_with('/') {
                    trimmed.to_string()
                } else {
                    format!("{trimmed}/")
                };
                Some(alias)
            }
        } else {
            detected
        }
    };

    if !json_output {
        print_add_project_structure(project_dir, &target_dir, &buyer_alias, ecosystem);
    }

    // Build src->dest map and file sets for import resolution
    let src_to_dest: HashMap<String, String> = files.iter().cloned().collect();
    let src_files: HashSet<String> = files.iter().map(|(s, _)| s.clone()).collect();
    let dest_files: HashSet<String> = files.iter().map(|(_, d)| d.clone()).collect();

    // Set up the rollback transaction.
    //
    // Open ONE `ManifestTransaction` covering source-file
    // copies AND dependency mutations + trailing install. The
    // transaction commits after the bare-imports notice; Swift
    // recursion, output, and skills intentionally run outside the tx
    // because they have their own scopes (Swift: recursive `run()`
    // owns its own tx; output: read-only; skills: best-effort,
    // non-fatal by contract).
    //
    // Validation happens via [`resolve_safe_dest_validate`] (pure, no mkdir);
    // the mkdir + post-mkdir canonicalize step
    // ([`prepare_safe_dest_parent`]) runs immediately after,
    // BEFORE the snapshot opens, so the canonicalized dest path is
    // pinned and identical between the snapshot read and the file
    // write. If the snapshot tracked the pre-canonicalize path while
    // the copy wrote to a different canonical path and an intermediate
    // symlink resolved differently between the two,
    // rollback would restore the wrong file. Sliding the mkdir
    // earlier means freshly-created parent directories live outside
    // the rollback boundary (a rolled-back failure leaves empty
    // parents on disk); that's a documented trade-off.
    let mut copied = 0;
    let mut skipped = 0;
    let mut file_actions: Vec<(String, String, String)> = Vec::new(); // (src, dest, action)
    let mut written_dest_paths: Vec<PathBuf> = Vec::with_capacity(files.len());
    std::fs::create_dir_all(&target_dir)?;
    let target_root_canonical = target_dir.canonicalize().map_err(|e| {
        LpmError::Registry(format!(
            "could not canonicalize target directory '{}': {e}",
            target_dir.display()
        ))
    })?;

    // Per-file: validate the dest_rel (no side effect), materialize +
    // canonicalize the parent (mkdir + post-canonicalize containment),
    // then compose the canonical-pinned final dest path. The copy loop
    // reads, conflict-checks, and writes through this exact path; the
    // tx snapshots it too. Snapshot path == write path; no TOCTOU
    // window between snapshot and write.
    let final_dest_paths: Vec<PathBuf> = files
        .iter()
        .map(|(_, dest_rel)| {
            let validated =
                resolve_safe_dest_validate(&target_root_canonical, &target_dir, dest_rel)?;
            let parent = validated.parent().ok_or_else(|| {
                LpmError::Registry(format!(
                    "destination '{}' has no parent",
                    validated.display()
                ))
            })?;
            let parent_canonical = prepare_safe_dest_parent(parent, &target_root_canonical)?;
            let file_name = validated.file_name().ok_or_else(|| {
                LpmError::Registry(format!(
                    "destination '{}' has no file name",
                    validated.display()
                ))
            })?;
            Ok::<PathBuf, LpmError>(parent_canonical.join(file_name))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Resolve `--pm auto` to a concrete PM so the tx can snapshot the
    // right per-PM lockfile alongside the LPM lockfiles.
    let pkg_json_path = project_dir.join("package.json");
    let lpm_lock_path = lpm_lockfile::Lockfile::read_for_project(project_dir).map_or_else(
        |_| project_dir.join(lpm_lockfile::LOCKFILE_NAME),
        |project| project.path,
    );
    let lpm_lock_bin_path = lpm_lock_path.with_extension("lockb");
    let added_sources_state_path = crate::added_sources_state::state_path(project_dir);
    let install_hash_path = project_dir.join(".lpm").join("install-hash");
    let effective_pm = if pm == "auto" {
        detect_package_manager(project_dir)
    } else {
        pm.to_string()
    };
    let pm_lockfiles = pm_lockfile_paths(&effective_pm, project_dir);

    // Optional snapshot list: manifest, LPM lockfiles, the selected
    // PM's lockfile(s), and every canonical-pinned dest path the copy
    // may touch. Manifest is `optional` (not `required`) because a
    // bare-template `lpm add` against a project with no `package.json`
    // is a valid path; the snapshot tolerates the absence and the
    // dep-install step warns separately.
    let mut optional_snapshot: Vec<&Path> = vec![
        pkg_json_path.as_path(),
        lpm_lock_path.as_path(),
        lpm_lock_bin_path.as_path(),
        added_sources_state_path.as_path(),
    ];
    for p in &pm_lockfiles {
        optional_snapshot.push(p.as_path());
    }
    for p in &final_dest_paths {
        optional_snapshot.push(p.as_path());
    }
    let tx = crate::manifest_tx::ManifestTransaction::snapshot_install_state(
        &[],
        &optional_snapshot,
        &[install_hash_path.as_path()],
    )
    .map_err(|e| LpmError::Registry(format!("failed to snapshot install state: {e}")))?;

    // Copy files to target (with import rewriting and conflict
    // resolution). Inside the tx scope — any `?` error from here
    // through the bare-imports notice drops the tx and rolls back every
    // snapshotted path (overwrites restored to original bytes; new files deleted)
    // plus invalidates `.lpm/install-hash` so the next install
    // re-derives state from a clean manifest.
    //
    // Destination-side path containment. Extraction-time traversal checks
    // cover the temp dir; the user-side write still needs its own
    // containment check. For arbitrary npm tarballs, a
    // malicious or buggy `dest_rel` could escape `target_dir` after
    // following an existing user-side symlink. The validate +
    // prepare phases above canonicalize the parent of every write,
    // refuse to write through existing symlinks, and reject any
    // destination whose canonical parent escapes
    // `target_root_canonical`. The copy loop reads, conflict-checks,
    // and writes through `final_dest_paths[i]` — the canonical-pinned
    // path computed above.
    for ((src_rel, dest_rel), dest_path) in files.iter().zip(final_dest_paths.iter()) {
        let src_path = temp_dir.path().join(src_rel);

        if !src_path.exists() {
            continue;
        }

        // Try to read as text for import rewriting
        let content = std::fs::read_to_string(&src_path).ok();
        let rewritten = content.as_deref().and_then(|text| {
            let ext = src_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
                return None;
            }
            crate::import_rewriter::rewrite_imports(
                text,
                src_rel,
                dest_rel,
                author_alias.as_deref(),
                buyer_alias.as_deref(),
                &src_to_dest,
                &src_files,
                &dest_files,
            )
        });

        let final_content = rewritten.as_deref().or(content.as_deref());

        let dest_existed = dest_path.exists();

        // Check for conflicts using diff-aware resolution
        if dest_existed {
            let action =
                handle_file_conflict(&src_path, dest_path, final_content, force, yes, json_output)?;
            match action {
                ConflictAction::Skip => {
                    skipped += 1;
                    file_actions.push((src_rel.clone(), dest_rel.clone(), "skip".to_string()));
                    continue;
                }
                ConflictAction::Overwrite => {
                    // Fall through to write
                }
            }
        }

        // Write (rewritten text or copy binary)
        if let Some(text) = final_content {
            std::fs::write(dest_path, text)?;
        } else {
            std::fs::copy(&src_path, dest_path)?;
        }
        copied += 1;
        written_dest_paths.push(dest_path.clone());
        file_actions.push((
            src_rel.clone(),
            dest_rel.clone(),
            if dest_existed { "overwrite" } else { "create" }.to_string(),
        ));
    }

    if !json_output {
        install_ui::done("Files copied");
        for (_, dest_rel, action) in &file_actions {
            if action != "skip" {
                print_add_file(dest_rel);
            }
        }
        if skipped > 0 {
            install_ui::skipped_untrusted(&format!(
                "{} {} unchanged",
                skipped,
                files_word(skipped)
            ));
        }
    }

    // Handle dependencies.
    //
    // Gate: only when `lpm.config.json` is present. The legacy fallback
    // at `handle_dependencies` would read the package's
    // own `package.json#dependencies + peerDependencies` whenever
    // `lpm.config.json#dependencies` was absent — fine for source-shape
    // packages on lpm.dev, but a footgun for arbitrary npm tarballs:
    // `lpm add typescript --yes` would silently bloat the user's
    // `package.json` with TypeScript's transitive deps. Simple-path
    // (no `lpm.config.json`) keeps the download-manager contract:
    // copy bytes, surface external imports, let the user install deps
    // themselves.
    let installed_deps = if !no_install_deps && lpm_config.is_some() {
        handle_dependencies(
            client,
            &route_table,
            project_dir,
            temp_dir.path(),
            &lpm_config,
            &inline_config,
            ecosystem,
            yes,
            json_output,
            no_engine_strict,
            !no_skills,
            &effective_pm,
        )
        .await?
    } else if !no_install_deps && lpm_config.is_none() {
        // Simple path → no auto-install. The bare-imports notice
        // below surfaces what the user should add themselves.
        Vec::new()
    } else {
        let count = count_dependencies(&lpm_config, &inline_config, temp_dir.path())?;
        if count > 0 && !json_output {
            install_ui::skipped_untrusted(&format!(
                "Skipped {count} dependencies (--no-install-deps)"
            ));
        }
        Vec::new()
    };
    let dep_count = installed_deps.len();
    if !json_output {
        for (name, spec) in &installed_deps {
            install_ui::plus(name, spec, None);
        }
    }

    // Bare-imports notice.
    //
    // Simple path (no `lpm.config.json`) only: walk every JS/TS file we
    // just copied, collect external/bare specifiers, and surface them
    // so the user knows which deps they need to install themselves.
    // Anti-drift: shares the `SpecifierKind` classifier with
    // `import_rewriter::rewrite_imports` so "bare" means the same thing
    // in both places.
    let external_imports: Vec<String> = if lpm_config.is_none() {
        let mut collected: HashSet<String> = HashSet::new();
        for (src_rel, _dest_rel) in &files {
            let src_path = temp_dir.path().join(src_rel);
            if !is_runtime_source_text_file(&src_path) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&src_path) {
                collected.extend(crate::import_rewriter::collect_bare_specifiers(
                    &text,
                    author_alias.as_deref(),
                ));
            }
        }
        let mut sorted: Vec<String> = collected.into_iter().collect();
        sorted.sort();
        sorted
    } else {
        Vec::new()
    };
    if !external_imports.is_empty() && !json_output {
        let external_imports = external_imports
            .iter()
            .map(|specifier| lpm_common::sanitize_terminal_inline(specifier).into_owned())
            .collect::<Vec<_>>();
        output::info(&format!(
            "Source uses external imports: {}\n  Make sure these are in your project's dependencies.",
            external_imports.join(", "),
        ));
    }

    // Persist exact source-delivery outputs so `lpm remove` can reverse the
    // add precisely for npm/private-registry packages and custom `--path`
    // installs, instead of guessing from a fixed directory list.
    let tracked_files = written_dest_paths
        .iter()
        .map(|path| crate::added_sources_state::manifest_path_for_file(project_dir, path));
    let tracked_skill_short = match (&target, no_skills) {
        (AddTarget::Lpm(pkg), false) => Some(pkg.short()),
        _ => None,
    };
    let mut added_sources_state = crate::added_sources_state::load_state(project_dir)?;
    added_sources_state.record_package_files(
        &target.json_name(),
        tracked_files,
        tracked_skill_short.as_deref(),
    );
    crate::added_sources_state::write_state(project_dir, &added_sources_state)?;

    // Commit the rollback transaction.
    //
    // File copy, dep mutation, trailing install, and the bare-imports
    // read-only notice all completed without error, so
    // the snapshotted bytes are stale and the project's new state is
    // the one we want to keep.
    //
    // The commit lands before Swift recursion on purpose:
    // `handle_swift_lpm_deps` recursively re-enters this function for
    // each Swift dep, and each recursive `lpm add` opens its own tx.
    // If the outer tx stayed open across that boundary, a recursive
    // failure could roll back the root package's already-applied
    // mutations while leaving the recursive `lpm add`'s side effects
    // intact — a worse split-brain than no rollback at all. Output and
    // skills are intentionally outside the tx for
    // the same reason: each owns a separate, narrower contract.
    tx.commit();

    // For Swift, handle recursive LPM dependencies.
    if ecosystem == "swift" {
        handle_swift_lpm_deps(
            client,
            project_dir,
            ver_meta,
            yes,
            json_output,
            force,
            dry_run,
            no_install_deps,
            no_skills,
            no_editor_setup,
            no_engine_strict,
            pm,
        )
        .await?;
    }

    // Output.
    if json_output {
        let mut json = serde_json::json!({
            "success": true,
            "package": {
                "name": target.json_name(),
                "version": version,
                "ecosystem": ecosystem,
            },
            "files": file_actions.iter().map(|(src, dest, action)| {
                serde_json::json!({
                    "src": src,
                    "dest": dest,
                    "action": action,
                })
            }).collect::<Vec<_>>(),
            "install_path": target_dir.strip_prefix(project_dir).unwrap_or(&target_dir).display().to_string(),
            "files_copied": copied,
            "files_skipped": skipped,
            "dependencies_installed": dep_count,
            "external_imports": external_imports,
            "config": inline_config,
            "alias": buyer_alias,
            "warnings": [],
            "errors": [],
        });
        if let Some(firewall_json) = firewall_json {
            json["firewall"] = firewall_json;
        }
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        if ver_meta.has_security_issues() {
            print_security_warnings(&target.display(), &version, ver_meta);
        }
        let elapsed = install_ui::green(&install_ui::format_duration(add_started.elapsed()));
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Done · added {} {} and {} {} in {}",
            copied,
            files_word(copied),
            dep_count,
            dependencies_word(dep_count),
            elapsed
        ));
    }

    // Install skills if this is an LPM package (respects --no-skills).
    //
    // Why @lpm.dev-only: lpm.dev runs LLM security scans on shipped skill
    // content at publish time, so the .md files we extract here are
    // attested. Arbitrary npm packages are not scanned, so we don't
    // extract their skills — opt-in npm-skills support would need an
    // explicit `--allow-skills` flag and an `lpm.config.json#skills`
    // declaration (deferred per the non-goals).
    if !no_skills && let AddTarget::Lpm(pkg) = &target {
        let short_name = pkg.short();
        let response = client.get_skills(&short_name, Some(&version)).await?;
        let result = crate::commands::skills::package::materialize(
            project_dir,
            &short_name,
            Some(&version),
            &response.skills,
        )?;
        crate::commands::install::ensure_skills_gitignore(project_dir);
        if !json_output {
            output::info(&format!(
                "Materialized {} package-published skill(s) for {}",
                result.installed,
                lpm_common::sanitize_terminal_inline(&short_name)
            ));
        }
    }

    Ok(())
}
