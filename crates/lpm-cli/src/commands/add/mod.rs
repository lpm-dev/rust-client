mod conflict;
mod dependencies;
mod display;
mod paths;
mod project;
mod security;
mod source;
mod swift;
mod target;

pub use security::{print_install_security_warnings, print_security_warnings};

use crate::commands::install::{
    NpmFirewallMaterializationPackage, prepare_npm_firewall_materialization_preflight,
    registry_materialization_route_is_public_npm,
    run_prepared_npm_firewall_materialization_preflight,
};
use crate::prompt::prompt_err;
use crate::{install_ui, output};
use conflict::{ConflictAction, handle_file_conflict};
use dependencies::{
    DependencyOutcome, collect_source_pkg_deps, handle_dependencies, pm_lockfile_paths,
    preflight_no_manifest_with_deps, refresh_dependency_install,
};
use display::{
    dependencies_word, files_word, handle_dry_run, print_add_file, print_add_project_structure,
};
use lpm_common::LpmError;
use lpm_registry::{RegistryClient, RouteTable};
use paths::{
    portable_destination_identity, prepare_safe_dest_parent, resolve_safe_dest_validate,
    validate_extracted_paths, validate_source_delivery_namespace,
};
use project::{
    detect_buyer_alias, detect_default_install_dir, detect_framework, detect_package_manager,
    planned_target_root, resolve_target_dir, validate_target_dir,
};
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use source::{
    collect_source_with_fallback, filter_config_files, is_runtime_source_text_file,
    json_value_to_config_string, read_lpm_config, resolve_noninteractive_required_config,
    validate_declared_config_values,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use swift::handle_swift_lpm_deps;
use target::{AddTarget, resolve_add_target};

#[derive(Serialize)]
struct AddJsonPackage<'a> {
    name: String,
    version: &'a str,
    ecosystem: &'a str,
}

#[derive(Serialize)]
struct AddJsonFile<'a> {
    src: &'a str,
    dest: &'a str,
    action: &'a str,
}

struct AddJsonFiles<'a>(&'a [(&'a str, &'a str, &'static str)]);

impl Serialize for AddJsonFiles<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (src, dest, action) in self.0 {
            sequence.serialize_element(&AddJsonFile { src, dest, action })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct AddJsonOutput<'a> {
    success: bool,
    package: AddJsonPackage<'a>,
    files: AddJsonFiles<'a>,
    install_path: String,
    files_copied: usize,
    files_skipped: usize,
    dependencies_installed: usize,
    external_imports: &'a [String],
    config: &'a HashMap<String, String>,
    alias: &'a Option<String>,
    warnings: &'a [String],
    errors: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    firewall: Option<serde_json::Value>,
}

fn ensure_unique_destinations(files: &[(String, String)]) -> Result<(), LpmError> {
    let mut destinations = HashSet::with_capacity(files.len());
    for (_, destination) in files {
        if !destinations.insert(destination.as_str()) {
            return Err(LpmError::Registry(format!(
                "source package declares destination '{destination}' more than once"
            )));
        }
    }
    Ok(())
}

fn validate_destination_plan(
    project_root_canonical: &Path,
    target_root_canonical: &Path,
    target_dir: &Path,
    files: &[(String, String)],
) -> Result<Vec<PathBuf>, LpmError> {
    let mut identities = HashSet::with_capacity(files.len());
    let mut destinations = Vec::with_capacity(files.len());
    for (_, destination) in files {
        let resolved = resolve_safe_dest_validate(target_root_canonical, target_dir, destination)?;
        validate_source_delivery_namespace(project_root_canonical, &resolved)?;
        let identity = portable_destination_identity(&resolved);
        if !identities.insert(identity) {
            return Err(LpmError::Registry(format!(
                "source package declares multiple paths for destination '{}'",
                resolved.display()
            )));
        }
        destinations.push(resolved);
    }
    Ok(destinations)
}

fn missing_destination_directories(
    project_dir: &Path,
    target_dir: &Path,
    files: &[(String, String)],
) -> Vec<PathBuf> {
    let mut missing = HashSet::new();
    let parents = std::iter::once(target_dir.to_path_buf()).chain(files.iter().filter_map(
        |(_, destination)| target_dir.join(destination).parent().map(Path::to_path_buf),
    ));
    for mut directory in parents {
        while directory.starts_with(project_dir) && directory != project_dir && !directory.exists()
        {
            missing.insert(directory.clone());
            let Some(parent) = directory.parent() else {
                break;
            };
            directory = parent.to_path_buf();
        }
    }
    missing.into_iter().collect()
}

fn missing_path_directories(project_dir: &Path, path: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let Some(mut directory) = path.parent() else {
        return missing;
    };
    while directory.starts_with(project_dir) && directory != project_dir && !directory.exists() {
        missing.push(directory.to_path_buf());
        let Some(parent) = directory.parent() else {
            break;
        };
        directory = parent;
    }
    missing
}

fn reconcile_stale_source_files(
    project_dir: &Path,
    package: &str,
    state: &crate::added_sources_state::AddedSourcesState,
    previous: Option<&crate::added_sources_state::AddedSourceRecord>,
    declared: &HashSet<PathBuf>,
    transaction: &mut crate::manifest_tx::ManifestTransaction,
    tracked_files: &mut Vec<(PathBuf, crate::added_sources_state::AddedSourceFile)>,
) -> Result<(), LpmError> {
    let Some(previous) = previous else {
        return Ok(());
    };

    for (manifest_path, file) in &previous.files {
        if declared.contains(manifest_path) {
            continue;
        }
        if state.packages.iter().any(|(other_package, record)| {
            other_package != package && record.files.contains_key(manifest_path)
        }) {
            continue;
        }

        let destination =
            crate::added_sources_state::resolve_tracked_manifest_path(project_dir, manifest_path)?;
        let Some(expected_digest) = file.installed_digest.as_deref() else {
            tracked_files.push((manifest_path.clone(), file.clone()));
            continue;
        };
        let current_digest = match std::fs::symlink_metadata(&destination) {
            Ok(_) => Some(crate::added_sources_state::digest_file(&destination)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(LpmError::Io(error)),
        };
        if current_digest
            .as_deref()
            .is_some_and(|digest| digest != expected_digest)
        {
            tracked_files.push((manifest_path.clone(), file.clone()));
            continue;
        }

        match (file.action, current_digest.is_some()) {
            (Some(crate::added_sources_state::AddedSourceFileAction::Create), true) => {
                transaction
                    .snapshot_optional_path(&destination)
                    .map_err(LpmError::Io)?;
                std::fs::remove_file(&destination).map_err(LpmError::Io)?;
            }
            (Some(crate::added_sources_state::AddedSourceFileAction::Create), false) => {}
            (Some(crate::added_sources_state::AddedSourceFileAction::Overwrite), true) => {
                let recorded_backup = file.backup_path.as_deref().ok_or_else(|| {
                    LpmError::Registry(format!(
                        "source state for '{}' is missing its overwrite backup",
                        manifest_path.display()
                    ))
                })?;
                let relative_backup = crate::added_sources_state::validate_recorded_backup_path(
                    package,
                    manifest_path,
                    recorded_backup,
                )?;
                let backup = crate::added_sources_state::validate_existing_backup(
                    project_dir,
                    &relative_backup,
                    file.backup_digest.as_deref(),
                )?;
                transaction
                    .snapshot_optional_path(&destination)
                    .map_err(LpmError::Io)?;
                transaction
                    .snapshot_optional_path(&backup)
                    .map_err(LpmError::Io)?;
                crate::added_sources_state::copy_file_atomic_with_digest(&backup, &destination)?;
                std::fs::remove_file(&backup).map_err(LpmError::Io)?;
            }
            (Some(crate::added_sources_state::AddedSourceFileAction::Overwrite), false) => {
                let recorded_backup = file.backup_path.as_deref().ok_or_else(|| {
                    LpmError::Registry(format!(
                        "source state for '{}' is missing its overwrite backup",
                        manifest_path.display()
                    ))
                })?;
                let relative_backup = crate::added_sources_state::validate_recorded_backup_path(
                    package,
                    manifest_path,
                    recorded_backup,
                )?;
                let backup = crate::added_sources_state::validate_existing_backup(
                    project_dir,
                    &relative_backup,
                    file.backup_digest.as_deref(),
                )?;
                transaction
                    .snapshot_optional_path(&destination)
                    .map_err(LpmError::Io)?;
                transaction
                    .snapshot_optional_path(&backup)
                    .map_err(LpmError::Io)?;
                crate::added_sources_state::copy_file_atomic_with_digest(&backup, &destination)?;
                std::fs::remove_file(&backup).map_err(LpmError::Io)?;
            }
            (None, _) => tracked_files.push((manifest_path.clone(), file.clone())),
        }
    }
    Ok(())
}

fn reconcile_stale_dependencies(
    project_dir: &Path,
    package: &str,
    state: &mut crate::added_sources_state::AddedSourcesState,
    previous: Option<&crate::added_sources_state::AddedSourceRecord>,
    desired: &HashSet<&str>,
) -> Result<bool, LpmError> {
    let Some(previous) = previous else {
        return Ok(false);
    };
    for (name, dependency) in previous
        .dependencies
        .iter()
        .filter(|(name, dependency)| dependency.inserted && !desired.contains(name.as_str()))
    {
        let replacement_owner = state.packages.iter().find_map(|(other_package, record)| {
            if other_package == package {
                return None;
            }
            record
                .dependencies
                .get(name)
                .filter(|candidate| {
                    candidate.spec == dependency.spec && candidate.section == dependency.section
                })
                .map(|_| other_package.clone())
        });
        if let Some(replacement_owner) = replacement_owner
            && let Some(replacement) = state
                .packages
                .get_mut(&replacement_owner)
                .and_then(|record| record.dependencies.get_mut(name))
        {
            replacement.inserted = true;
        }
    }
    let stale = previous
        .dependencies
        .iter()
        .filter(|(name, dependency)| {
            dependency.inserted
                && !desired.contains(name.as_str())
                && !state.packages.iter().any(|(other_package, record)| {
                    other_package != package && record.dependencies.contains_key(name.as_str())
                })
        })
        .collect::<Vec<_>>();
    if stale.is_empty() {
        return Ok(false);
    }

    let manifest_path = project_dir.join("package.json");
    let content =
        lpm_common::read_text_file_capped(&manifest_path, lpm_common::CONFIG_FILE_SIZE_CAP_BYTES)
            .map_err(|error| LpmError::Registry(format!("failed to read package.json: {error}")))?;
    let mut manifest: serde_json::Value = serde_json::from_str(&content)
        .map_err(|error| LpmError::Registry(format!("failed to parse package.json: {error}")))?;
    let object = manifest
        .as_object_mut()
        .ok_or_else(|| LpmError::Registry("package.json root must be a JSON object".to_string()))?;
    let mut changed = false;
    for (name, dependency) in stale {
        let Some(section) = object
            .get_mut(&dependency.section)
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        if section.get(name).and_then(serde_json::Value::as_str) == Some(dependency.spec.as_str()) {
            section.remove(name);
            changed = true;
        }
    }
    if changed {
        let mut body = serde_json::to_vec_pretty(&manifest).map_err(|error| {
            LpmError::Registry(format!("failed to serialize package.json: {error}"))
        })?;
        body.push(b'\n');
        lpm_common::write_file_atomic(&manifest_path, body).map_err(LpmError::Io)?;
    }
    Ok(changed)
}

fn exclusively_owned_dependencies(
    package: &str,
    state: &crate::added_sources_state::AddedSourcesState,
    previous: Option<&crate::added_sources_state::AddedSourceRecord>,
) -> HashMap<String, crate::added_sources_state::AddedSourceDependency> {
    previous
        .into_iter()
        .flat_map(|record| &record.dependencies)
        .filter(|(name, dependency)| {
            dependency.inserted
                && !state.packages.iter().any(|(other_package, record)| {
                    other_package != package && record.dependencies.contains_key(name.as_str())
                })
        })
        .map(|(name, dependency)| (name.clone(), dependency.clone()))
        .collect()
}

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
    crate::commands::install::workspace_lockfile::scope_member_install(
        project_dir,
        run_locked(
            client,
            project_dir,
            package_spec,
            target_path,
            yes,
            json_output,
            force,
            dry_run,
            no_install_deps,
            no_skills,
            no_editor_setup,
            no_engine_strict,
            pm,
            alias_override,
            swift_target,
        ),
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "the locked command keeps its complete CLI and registry context explicit"
)]
async fn run_locked(
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
    let resolver_policy = crate::release_age_selection::resolver_policy_for_project(
        project_dir,
        None,
        false,
        json_output,
    )?;
    let version = if let Some(v) = &version_spec {
        crate::release_age_selection::resolve_version_spec_with_policy(
            &metadata,
            v,
            &resolver_policy,
        )?
    } else {
        crate::release_age_selection::latest_allowed_version_or_policy_error(
            &metadata,
            &resolver_policy,
        )?
    };

    let ver_meta = metadata
        .version(&version)
        .cloned()
        .ok_or_else(|| LpmError::NotFound(format!("version {version} not found")))?;
    let integrity = ver_meta.integrity_or_shasum().ok_or_else(|| {
        LpmError::Registry(format!(
            "refusing to install {}@{version}: registry metadata has no integrity or shasum",
            target.display()
        ))
    })?;
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
                Some(integrity.as_ref()),
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
    drop(metadata);

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
    if downloaded.sri != integrity.as_ref()
        && let Err(e) =
            lpm_extractor::verify_integrity_file(downloaded.file.path(), integrity.as_ref())
    {
        return Err(LpmError::Registry(format!(
            "integrity verification failed for {}@{}: {e}",
            target.display(),
            version
        )));
    }

    // Extract tarball from the spooled file (bounded-memory
    // path).
    let temp_dir = tempfile::tempdir().map_err(LpmError::Io)?;
    let extracted_paths =
        lpm_extractor::extract_tarball_from_file(downloaded.file.path(), temp_dir.path())?;

    // Validate extracted paths for path traversal. The user-side
    // write-time containment check happens before copying files.
    validate_extracted_paths(&extracted_paths, temp_dir.path())?;
    drop(extracted_paths);

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

    if let Some(config) = &lpm_config {
        validate_declared_config_values(config, &mut inline_config)?;
    }

    // Config schema interactive prompts.
    if let Some(config) = &lpm_config
        && let Some(schema) = config.get("configSchema").and_then(|s| s.as_object())
        && !yes
        && !json_output
        && is_tty
    {
        for (key, field) in schema {
            if inline_config.contains_key(key) {
                continue;
            }

            let field_type = field
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("string");
            let required = field
                .get("required")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
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
                    if !required && default_val.is_empty() {
                        let chosen: String = cliclack::select(safe_label)
                            .item(String::new(), "Leave unset", "")
                            .item("true".to_string(), "Yes", "")
                            .item("false".to_string(), "No", "")
                            .initial_value(String::new())
                            .interact()
                            .map_err(prompt_err)?;
                        if !chosen.is_empty() {
                            inline_config.insert(key.clone(), chosen);
                        }
                    } else {
                        let result = cliclack::confirm(safe_label)
                            .initial_value(default_val == "true")
                            .interact()
                            .map_err(prompt_err)?;
                        inline_config.insert(key.clone(), result.to_string());
                    }
                }
                "select" => {
                    let multi = field
                        .get("multiSelect")
                        .and_then(|m| m.as_bool())
                        .unwrap_or(false);
                    let options: Vec<(String, String)> = field
                        .get("options")
                        .and_then(|o| o.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| {
                                    if let Some(s) = v.as_str() {
                                        Some((s.to_string(), s.to_string()))
                                    } else {
                                        let value = v.get("value").and_then(|vv| vv.as_str())?;
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
                            ms = ms.item(value.clone(), crate::prompt::untrusted(label_str), "");
                        }
                        let defaults = default_val
                            .split(',')
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(str::to_string)
                            .collect();
                        ms = ms.initial_values(defaults);
                        let selected_values: Vec<String> = ms.interact().map_err(prompt_err)?;
                        let selected: Vec<&str> =
                            selected_values.iter().map(|s| s.as_str()).collect();
                        inline_config.insert(key.clone(), selected.join(","));
                    } else {
                        let optional_unset = !required && default_val.is_empty();
                        let default_idx = values
                            .iter()
                            .position(|v| *v == default_val.as_str())
                            .unwrap_or(0);
                        let mut sel = cliclack::select(safe_label);
                        if optional_unset {
                            sel = sel.item(String::new(), "Leave unset", "");
                            sel = sel.initial_value(String::new());
                        }
                        for (i, (value, label_str)) in options.iter().enumerate() {
                            sel = sel.item(value.clone(), crate::prompt::untrusted(label_str), "");
                            if i == default_idx {
                                sel = sel.initial_value(value.clone());
                            }
                        }
                        let chosen: String = sel.interact().map_err(prompt_err)?;
                        if !chosen.is_empty() {
                            inline_config.insert(key.clone(), chosen);
                        }
                    }
                }
                _ => {
                    let value: String = cliclack::input(safe_label)
                        .default_input(&crate::prompt::untrusted(&default_val))
                        .required(required)
                        .interact()
                        .map_err(prompt_err)?;
                    if !value.is_empty() {
                        inline_config.insert(key.clone(), value);
                    }
                }
            }
        }
    }
    if !is_non_interactive && let Some(config) = &lpm_config {
        validate_declared_config_values(config, &mut inline_config)?;
    }
    if is_non_interactive && let Some(config) = &lpm_config {
        resolve_noninteractive_required_config(config, &mut inline_config)?;
    }

    // Detect ecosystem and determine target.
    let ecosystem = lpm_config
        .as_ref()
        .and_then(|c| c.get("ecosystem").and_then(|v| v.as_str()))
        .unwrap_or("js");
    let framework = if ecosystem == "swift" {
        "swift".to_string()
    } else {
        detect_framework(project_dir)
    };

    // Interactive target directory selection.
    let target_dir = if target_path.is_some() {
        resolve_target_dir(
            project_dir,
            target_path,
            ecosystem,
            &framework,
            swift_target,
        )
    } else if !yes && !json_output && is_tty && ecosystem != "swift" {
        let default_dir = detect_default_install_dir(project_dir, &framework);
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
        resolve_target_dir(
            project_dir,
            target_path,
            ecosystem,
            &framework,
            swift_target,
        )
    };
    validate_target_dir(project_dir, &target_dir)?;
    let target_root_planned = planned_target_root(&target_dir)?;

    // Build file list (config-based, lpm.source fallback, or all files).
    let files = if let Some(config) = &lpm_config {
        if let Some(files_arr) = config.get("files").and_then(|f| f.as_array()) {
            filter_config_files(temp_dir.path(), files_arr, &inline_config)?
        } else {
            collect_source_with_fallback(temp_dir.path())?
        }
    } else {
        collect_source_with_fallback(temp_dir.path())?
    };

    if files.is_empty() {
        return Err(LpmError::Registry("no files to install".into()));
    }
    ensure_unique_destinations(&files)?;
    let project_root_canonical = project_dir.canonicalize().map_err(LpmError::Io)?;
    validate_destination_plan(
        &project_root_canonical,
        &target_root_planned,
        &target_dir,
        &files,
    )?;
    let planned_dependency_entries = if lpm_config.is_some() {
        collect_source_pkg_deps(&lpm_config, &inline_config, temp_dir.path())?
    } else {
        Vec::new()
    };

    preflight_no_manifest_with_deps(
        project_dir,
        no_install_deps,
        planned_dependency_entries.len(),
    )?;

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
            json_output,
            no_install_deps,
            planned_dependency_entries.len(),
        );
    }

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
        let detected = detect_buyer_alias(project_dir, &target_dir);

        if !yes && !json_output && is_tty {
            // Build a sensible default: detected alias + target relative path
            let default_alias = if let Some(ref alias) = detected {
                alias.clone()
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
        print_add_project_structure(
            project_dir,
            &target_dir,
            &buyer_alias,
            ecosystem,
            &framework,
        );
    }

    let src_to_dest: HashMap<&str, &str> = files
        .iter()
        .map(|(source, destination)| (source.as_str(), destination.as_str()))
        .collect();
    let dest_files: HashSet<&str> = files
        .iter()
        .map(|(_, destination)| destination.as_str())
        .collect();

    // Destination validation first runs without filesystem mutations.
    // The transaction then owns every directory creation, file write, and
    // dependency mutation through the final install.
    let mut copied = 0;
    let mut skipped = 0;
    let mut file_actions: Vec<(&str, &str, &'static str)> = Vec::with_capacity(files.len());
    let mut tracked_files = Vec::with_capacity(files.len());
    let mut collected_external_imports = HashSet::new();
    let rollback_dirs = missing_destination_directories(project_dir, &target_dir, &files);

    let pkg_json_path = project_dir.join("package.json");
    let lpm_lock_path =
        crate::commands::install::workspace_lockfile::active_lockfile_path(project_dir);
    let lpm_lock_bin_path = lpm_lock_path.with_extension("lockb");
    let added_sources_state_path = crate::added_sources_state::state_path(project_dir);
    let (mut added_sources_state, added_sources_state_snapshot) =
        crate::added_sources_state::load_state_with_snapshot(project_dir)?;
    let install_hash_path = project_dir.join(".lpm").join("install-hash");
    let effective_pm = if pm == "auto" {
        detect_package_manager(project_dir)
    } else {
        pm.to_string()
    };
    let pm_lockfiles = pm_lockfile_paths(&effective_pm, project_dir);

    // The package manifest is optional because dependency-free source can be
    // delivered before project initialization.
    let mut optional_snapshot: Vec<&Path> = vec![
        pkg_json_path.as_path(),
        lpm_lock_path.as_path(),
        lpm_lock_bin_path.as_path(),
    ];
    for p in &pm_lockfiles {
        optional_snapshot.push(p.as_path());
    }
    let mut tx = crate::manifest_tx::ManifestTransaction::snapshot_install_state(
        &[],
        &optional_snapshot,
        &[install_hash_path.as_path()],
    )
    .map_err(|e| LpmError::Registry(format!("failed to snapshot install state: {e}")))?;
    tx.snapshot_optional_path_with_bytes(&added_sources_state_path, added_sources_state_snapshot)
        .map_err(|error| {
            LpmError::Registry(format!(
                "failed to snapshot added-source state '{}': {error}",
                added_sources_state_path.display()
            ))
        })?;
    tx.remove_dirs_on_rollback(rollback_dirs);
    let package_state_key = target.json_name();
    let previous_package_record = added_sources_state.package(&package_state_key).cloned();

    std::fs::create_dir_all(&target_dir)?;
    let target_root_canonical = target_dir.canonicalize().map_err(|e| {
        LpmError::Registry(format!(
            "could not canonicalize target directory '{}': {e}",
            target_dir.display()
        ))
    })?;
    let mut canonical_parents = HashMap::<PathBuf, PathBuf>::new();
    let final_dest_paths: Vec<PathBuf> = validate_destination_plan(
        &project_root_canonical,
        &target_root_canonical,
        &target_dir,
        &files,
    )?
    .into_iter()
    .map(|validated| {
        let parent = validated.parent().ok_or_else(|| {
            LpmError::Registry(format!(
                "destination '{}' has no parent",
                validated.display()
            ))
        })?;
        let parent_canonical = if let Some(canonical) = canonical_parents.get(parent) {
            canonical.clone()
        } else {
            let canonical = prepare_safe_dest_parent(parent, &target_root_canonical)?;
            canonical_parents.insert(parent.to_path_buf(), canonical.clone());
            canonical
        };
        let file_name = validated.file_name().ok_or_else(|| {
            LpmError::Registry(format!(
                "destination '{}' has no file name",
                validated.display()
            ))
        })?;
        Ok::<PathBuf, LpmError>(parent_canonical.join(file_name))
    })
    .collect::<Result<Vec<_>, _>>()?;

    let mut final_identities = HashSet::with_capacity(final_dest_paths.len());
    for destination in &final_dest_paths {
        validate_source_delivery_namespace(&project_root_canonical, destination)?;
        let identity = portable_destination_identity(destination);
        if !final_identities.insert(identity) {
            return Err(LpmError::Registry(format!(
                "source package resolves multiple files to destination '{}'",
                destination.display()
            )));
        }
    }
    let declared_manifest_paths: HashSet<PathBuf> = final_dest_paths
        .iter()
        .map(|path| crate::added_sources_state::manifest_path_for_file(project_dir, path))
        .collect();

    // Writes use the prepared canonical paths. Re-resolving authored paths
    // here would reintroduce package-controlled link traversal.
    for ((src_rel, dest_rel), dest_path) in files.iter().zip(final_dest_paths.iter()) {
        let src_path = temp_dir.path().join(src_rel);

        let content = if is_runtime_source_text_file(&src_path) {
            std::fs::read_to_string(&src_path).ok()
        } else {
            None
        };
        if lpm_config.is_none()
            && let Some(text) = content.as_deref()
        {
            collected_external_imports.extend(crate::import_rewriter::collect_bare_specifiers(
                text,
                author_alias.as_deref(),
            ));
        }
        let rewritten = content.as_deref().and_then(|text| {
            crate::import_rewriter::rewrite_imports_indexed(
                text,
                src_rel,
                dest_rel,
                author_alias.as_deref(),
                buyer_alias.as_deref(),
                &src_to_dest,
                &dest_files,
            )
        });

        let final_content = rewritten.as_deref().or(content.as_deref());

        let dest_existed = dest_path.exists();
        let manifest_path =
            crate::added_sources_state::manifest_path_for_file(project_dir, dest_path);
        let previous_file = previous_package_record
            .as_ref()
            .and_then(|record| record.files.get(&manifest_path))
            .cloned();
        let current_digest = (dest_existed && previous_file.is_some())
            .then(|| crate::added_sources_state::digest_file(dest_path))
            .transpose()?;
        let previous_is_current = previous_file.as_ref().is_some_and(|previous| {
            previous.installed_digest.as_ref() == current_digest.as_ref()
                && previous.action.is_some()
        });

        // Check for conflicts using diff-aware resolution
        if dest_existed && !previous_is_current {
            let action =
                handle_file_conflict(&src_path, dest_path, final_content, force, yes, json_output)?;
            match action {
                ConflictAction::Skip => {
                    skipped += 1;
                    if let Some(previous) = previous_package_record
                        .as_ref()
                        .and_then(|record| record.files.get(&manifest_path))
                    {
                        tracked_files.push((manifest_path, previous.clone()));
                    }
                    file_actions.push((src_rel.as_str(), dest_rel.as_str(), "skip"));
                    continue;
                }
                ConflictAction::Overwrite => {
                    // Fall through to write
                }
            }
        }

        let (source_action, backup_path, backup_digest, backup_mode, destination_snapshot) =
            if dest_existed && previous_is_current {
                let previous = previous_file.as_ref().expect("checked above");
                if previous.action
                    == Some(crate::added_sources_state::AddedSourceFileAction::Overwrite)
                {
                    let recorded_backup = previous.backup_path.as_ref().ok_or_else(|| {
                        LpmError::Registry(format!(
                            "source state for '{}' is missing its overwrite backup",
                            manifest_path.display()
                        ))
                    })?;
                    let backup_path = crate::added_sources_state::validate_recorded_backup_path(
                        &package_state_key,
                        &manifest_path,
                        recorded_backup,
                    )?;
                    crate::added_sources_state::validate_existing_backup(
                        project_dir,
                        &backup_path,
                        previous.backup_digest.as_deref(),
                    )?;
                }
                (
                    previous.action.expect("checked above"),
                    previous
                        .backup_path
                        .as_deref()
                        .map(|recorded| {
                            crate::added_sources_state::validate_recorded_backup_path(
                                &package_state_key,
                                &manifest_path,
                                recorded,
                            )
                        })
                        .transpose()?,
                    previous.backup_digest.clone(),
                    previous.backup_mode,
                    None,
                )
            } else if dest_existed {
                let backup_path = crate::added_sources_state::backup_path_for_file(
                    &package_state_key,
                    &manifest_path,
                );
                let absolute_backup = project_dir.join(&backup_path);
                tx.remove_dirs_on_rollback(missing_path_directories(project_dir, &absolute_backup));
                tx.snapshot_optional_path(&absolute_backup)
                    .map_err(|error| {
                        LpmError::Registry(format!(
                            "failed to snapshot source backup '{}': {error}",
                            absolute_backup.display()
                        ))
                    })?;
                let written_backup =
                    crate::added_sources_state::write_backup(project_dir, &backup_path, dest_path)?;
                let destination_snapshot =
                    std::fs::File::open(&absolute_backup).map_err(LpmError::Io)?;
                (
                    crate::added_sources_state::AddedSourceFileAction::Overwrite,
                    Some(backup_path),
                    Some(written_backup.digest),
                    written_backup.original_mode,
                    Some(destination_snapshot),
                )
            } else if previous_file.as_ref().is_some_and(|previous| {
                previous.action
                    == Some(crate::added_sources_state::AddedSourceFileAction::Overwrite)
            }) {
                let previous = previous_file.as_ref().expect("checked above");
                let recorded_backup = previous.backup_path.as_ref().ok_or_else(|| {
                    LpmError::Registry(format!(
                        "source state for '{}' is missing its overwrite backup",
                        manifest_path.display()
                    ))
                })?;
                let backup_path = crate::added_sources_state::validate_recorded_backup_path(
                    &package_state_key,
                    &manifest_path,
                    recorded_backup,
                )?;
                crate::added_sources_state::validate_existing_backup(
                    project_dir,
                    &backup_path,
                    previous.backup_digest.as_deref(),
                )?;
                (
                    crate::added_sources_state::AddedSourceFileAction::Overwrite,
                    Some(backup_path),
                    previous.backup_digest.clone(),
                    previous.backup_mode,
                    None,
                )
            } else {
                if previous_file
                    .as_ref()
                    .is_some_and(|previous| previous.backup_path.is_some())
                {
                    return Err(LpmError::Registry(format!(
                        "source state for '{}' has a backup without overwrite ownership",
                        manifest_path.display()
                    )));
                }
                (
                    crate::added_sources_state::AddedSourceFileAction::Create,
                    None,
                    None,
                    None,
                    None,
                )
            };
        // Write (rewritten text or copy binary)
        let snapshot_result = if let Some(snapshot) = destination_snapshot {
            tx.snapshot_optional_path_from_file(dest_path, snapshot)
        } else {
            tx.snapshot_optional_path(dest_path)
        };
        snapshot_result.map_err(|error| {
            LpmError::Registry(format!(
                "failed to snapshot destination '{}': {error}",
                dest_path.display()
            ))
        })?;
        let installed_digest = if let Some(text) = final_content {
            lpm_common::write_file_atomic(dest_path, text).map_err(LpmError::Io)?;
            crate::added_sources_state::digest_bytes(text.as_bytes())
        } else {
            crate::added_sources_state::copy_file_atomic_with_digest(&src_path, dest_path)?
        };
        copied += 1;
        tracked_files.push((
            manifest_path,
            crate::added_sources_state::AddedSourceFile {
                source: Some(PathBuf::from(src_rel)),
                installed_digest: Some(installed_digest),
                action: Some(source_action),
                backup_path,
                backup_digest,
                backup_mode,
            },
        ));
        file_actions.push((
            src_rel.as_str(),
            dest_rel.as_str(),
            if dest_existed { "overwrite" } else { "create" },
        ));
    }

    if !json_output {
        install_ui::done("Files copied");
        for (_, dest_rel, action) in &file_actions {
            if *action != "skip" {
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

    reconcile_stale_source_files(
        project_dir,
        &package_state_key,
        &added_sources_state,
        previous_package_record.as_ref(),
        &declared_manifest_paths,
        &mut tx,
        &mut tracked_files,
    )?;

    let desired_dependency_names: HashSet<&str> = planned_dependency_entries
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    let exclusively_owned_dependencies = exclusively_owned_dependencies(
        &package_state_key,
        &added_sources_state,
        previous_package_record.as_ref(),
    );
    let removed_stale_dependencies = if no_install_deps {
        false
    } else {
        reconcile_stale_dependencies(
            project_dir,
            &package_state_key,
            &mut added_sources_state,
            previous_package_record.as_ref(),
            &desired_dependency_names,
        )?
    };

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
    let dependency_outcome = if !no_install_deps && lpm_config.is_some() {
        handle_dependencies(
            client,
            &route_table,
            project_dir,
            &planned_dependency_entries,
            &exclusively_owned_dependencies,
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
        DependencyOutcome {
            requirements: Vec::new(),
            inserted: Vec::new(),
        }
    } else {
        let count = planned_dependency_entries.len();
        if count > 0 && !json_output {
            install_ui::skipped_untrusted(&format!(
                "Skipped {count} dependencies (--no-install-deps)"
            ));
        }
        DependencyOutcome {
            requirements: Vec::new(),
            inserted: Vec::new(),
        }
    };
    if removed_stale_dependencies && dependency_outcome.requirements.is_empty() {
        refresh_dependency_install(
            client,
            project_dir,
            json_output,
            no_engine_strict,
            !no_skills,
            &effective_pm,
        )
        .await?;
    }
    let installed_deps = &dependency_outcome.inserted;
    let dep_count = installed_deps.len();
    if !json_output {
        for (name, spec) in installed_deps {
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
        let mut sorted: Vec<String> = collected_external_imports.into_iter().collect();
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
    let tracked_skill_short = match (&target, no_skills) {
        (AddTarget::Lpm(pkg), false) => Some(pkg.short()),
        _ => None,
    };
    let tracked_dependencies = (!no_install_deps && lpm_config.is_some()).then(|| {
        dependency_outcome
            .requirements
            .into_iter()
            .map(|requirement| {
                (
                    requirement.name,
                    crate::added_sources_state::AddedSourceDependency {
                        spec: requirement.spec,
                        section: requirement.section,
                        inserted: requirement.inserted,
                    },
                )
            })
            .collect()
    });
    added_sources_state.record_package_delivery(
        &package_state_key,
        tracked_files,
        tracked_dependencies,
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
    crate::commands::install::workspace_lockfile::commit_manifest_transaction(tx);

    // For Swift, handle recursive LPM dependencies.
    if ecosystem == "swift" {
        handle_swift_lpm_deps(
            client,
            project_dir,
            &ver_meta,
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

    let mut warnings = Vec::new();
    if !no_skills && let AddTarget::Lpm(pkg) = &target {
        let short_name = pkg.short();
        let skills_result = async {
            let response = client.get_skills(&short_name, Some(&version)).await?;
            let result = crate::commands::skills::package::materialize(
                project_dir,
                &short_name,
                Some(&version),
                &response.skills,
            )?;
            crate::commands::install::ensure_skills_gitignore(project_dir);
            Ok::<_, LpmError>(result.installed)
        }
        .await;
        match skills_result {
            Ok(installed) if !json_output => output::info(&format!(
                "Materialized {installed} package-published skill(s) for {}",
                lpm_common::sanitize_terminal_inline(&short_name)
            )),
            Ok(_) => {}
            Err(error) => {
                let warning = format!(
                    "source files were added, but package skills for {short_name} could not be materialized: {error}"
                );
                if !json_output {
                    output::warn(&warning);
                }
                warnings.push(warning);
            }
        }
    }

    // Output.
    if json_output {
        let output = AddJsonOutput {
            success: true,
            package: AddJsonPackage {
                name: target.json_name(),
                version: &version,
                ecosystem,
            },
            files: AddJsonFiles(&file_actions),
            install_path: target_dir
                .strip_prefix(project_dir)
                .unwrap_or(&target_dir)
                .display()
                .to_string(),
            files_copied: copied,
            files_skipped: skipped,
            dependencies_installed: dep_count,
            external_imports: &external_imports,
            config: &inline_config,
            alias: &buyer_alias,
            warnings: &warnings,
            errors: &[],
            firewall: firewall_json,
        };
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer_pretty(&mut stdout, &output).map_err(|error| {
            LpmError::Registry(format!("failed to serialize add output: {error}"))
        })?;
        use std::io::Write as _;
        stdout.write_all(b"\n").map_err(LpmError::Io)?;
    } else {
        if ver_meta.has_security_issues() {
            print_security_warnings(&target.display(), &version, &ver_meta);
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

    Ok(())
}
