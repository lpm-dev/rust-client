use crate::install_ui;
use crate::npm_public_source::{NpmMetadataSource, lockfile_npm_metadata_source};
use crate::prompt::prompt_err;
#[cfg(test)]
use crate::upgrade_engine::PeerViolation;
use crate::upgrade_engine::{self, PatchInvalidation, PeerImpact, SemverClass};
use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName};
use lpm_registry::PackageMetadata;
use lpm_registry::RegistryClient;
use lpm_resolver::specifier::Specifier;
use lpm_semver::Version;
use std::collections::{BTreeSet, HashMap};
use std::io::IsTerminal;
use std::path::Path;
use std::time::Instant;

// ── Mode resolution ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedMode {
    Interactive,
    NonInteractive,
}

fn resolve_mode(
    interactive: bool,
    yes: bool,
    json_output: bool,
    is_tty: bool,
) -> Result<ResolvedMode, LpmError> {
    if interactive && yes {
        return Err(LpmError::Script(
            "`-i` and `-y` are mutually exclusive \
			 (one forces interactive, the other forces non-interactive)"
                .into(),
        ));
    }
    if interactive && json_output {
        return Err(LpmError::Script(
            "`-i` cannot be combined with `--json` — \
			 interactive prompts cannot render structured output"
                .into(),
        ));
    }
    if yes || json_output {
        return Ok(ResolvedMode::NonInteractive);
    }
    if interactive {
        return Ok(ResolvedMode::Interactive);
    }
    if is_tty {
        Ok(ResolvedMode::Interactive)
    } else {
        Ok(ResolvedMode::NonInteractive)
    }
}

fn validate_major_for_mode(major: bool, mode: ResolvedMode) -> Result<(), LpmError> {
    if major && mode == ResolvedMode::Interactive {
        return Err(LpmError::Script(
            "`--major` cannot be combined with interactive mode. \
			 In interactive mode, major upgrades appear as separate rows \
			 alongside the safe within-major option — toggle them on individually. \
			 Pass `-y --major` for batch behavior, or just `lpm upgrade` \
			 and select the MAJOR rows you want."
                .into(),
        ));
    }
    Ok(())
}

// ── Candidate types ─────────────────────────────────────────────────

/// Distinguishes the two rows a single package can produce in interactive
/// mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    WithinMajor,
    AbsoluteLatest,
}

#[derive(Debug, Clone)]
enum MetadataLookup {
    Lpm(PackageName),
    Npm(NpmMetadataSource),
}

#[derive(Debug, Clone)]
enum ManifestDependencySpec {
    Plain,
    NpmAlias { target: String },
}

impl ManifestDependencySpec {
    fn from_manifest_value(name: &str, value: &str) -> Result<(Self, String), LpmError> {
        if value.trim_start().starts_with("npm:") {
            return match Specifier::parse(value) {
                Ok(Specifier::NpmAlias { target, range }) => Ok((Self::NpmAlias { target }, range)),
                Ok(_) => Err(LpmError::Script(format!(
                    "dependency `{name}` uses invalid npm alias spec `{value}`"
                ))),
                Err(err) => Err(LpmError::Script(format!(
                    "dependency `{name}` uses invalid npm alias spec `{value}`: {err}"
                ))),
            };
        }

        Ok((Self::Plain, value.to_string()))
    }

    fn render_new_value(&self, new_range: &str) -> String {
        match self {
            Self::Plain => new_range.to_string(),
            Self::NpmAlias { target } => format!("npm:{target}@{new_range}"),
        }
    }
}

fn dependency_lookup_name(
    manifest_name: &str,
    manifest_spec: &ManifestDependencySpec,
    lockfile: Option<&lpm_lockfile::Lockfile>,
) -> String {
    match manifest_spec {
        ManifestDependencySpec::NpmAlias { target } => target.clone(),
        ManifestDependencySpec::Plain => lockfile
            .and_then(|lf| lf.root_aliases.get(manifest_name))
            .cloned()
            .unwrap_or_else(|| manifest_name.to_string()),
    }
}

#[derive(Debug, Clone)]
struct UpgradeDependency {
    name: String,
    lookup_name: String,
    range: String,
    manifest_value: String,
    is_dev: bool,
    lookup: MetadataLookup,
    manifest_spec: ManifestDependencySpec,
}

/// enriched candidate — drives both the interactive multiselect
/// and the JSON output.
#[derive(Clone)]
struct EnrichedCandidate {
    name: String,
    from: String,
    current_range: String,
    new_range: String,
    to: String,
    is_dev: bool,
    target_kind: TargetKind,
    semver_class: SemverClass,
    has_install_scripts: bool,
    peer_impact: PeerImpact,
    patch_invalidation: Option<PatchInvalidation>,
}

// ── Entry point ─────────────────────────────────────────────────────

/// Upgrade outdated LPM dependencies to their latest versions.
///
/// TTY-aware interactive mode with enrichment.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    requested_packages: &[String],
    major: bool,
    dry_run: bool,
    interactive: bool,
    yes: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let started_at = Instant::now();
    let pkg_json_path = project_dir.join("package.json");
    let original_content = match lpm_common::read_text_file_capped(
        &pkg_json_path,
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => content,
        Err(lpm_common::BoundedReadError::NotFound { .. }) => {
            return Err(LpmError::NotFound("no package.json found".into()));
        }
        Err(error) => {
            return Err(LpmError::Script(format!(
                "failed to read package.json: {error}"
            )));
        }
    };
    let mut doc: serde_json::Value = serde_json::from_str(&original_content)
        .map_err(|e| LpmError::Script(format!("failed to parse package.json: {e}")))?;

    let pkg_typed = lpm_workspace::read_package_json(&pkg_json_path)
        .map_err(|e| LpmError::Registry(format!("failed to read package.json: {e}")))?;
    let patched_deps = pkg_typed
        .lpm
        .as_ref()
        .map(|c| c.patched_dependencies.clone())
        .unwrap_or_default();

    // Resolve mode + validate flag combinations
    let is_tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let mode = resolve_mode(interactive, yes, json_output, is_tty)?;
    validate_major_for_mode(major, mode)?;
    let release_age_policy = crate::release_age_selection::resolver_policy_for_project(
        project_dir,
        None,
        false,
        json_output,
    )?;

    // Read lockfile ONCE
    let lockfile_path = project_dir.join("lpm.lock");
    let lockfile = if lockfile_path.exists() {
        lpm_lockfile::Lockfile::read_fast(&lockfile_path).ok()
    } else {
        None
    };

    let mut skipped_private: Vec<String> = Vec::new();
    let all_deps = filter_requested_deps(extract_deps_from_value(&doc), requested_packages)?;
    let mut upgradeable_deps = Vec::with_capacity(all_deps.len());
    for (name, manifest_value, is_dev) in all_deps {
        let (manifest_spec, range) =
            ManifestDependencySpec::from_manifest_value(&name, &manifest_value)?;
        let lookup_name = dependency_lookup_name(&name, &manifest_spec, lockfile.as_ref());

        if lookup_name.starts_with("@lpm.dev/") {
            if let Ok(pkg_name) = PackageName::parse(&lookup_name) {
                upgradeable_deps.push(UpgradeDependency {
                    name,
                    lookup_name,
                    range,
                    manifest_value,
                    is_dev,
                    lookup: MetadataLookup::Lpm(pkg_name),
                    manifest_spec,
                });
            }
            continue;
        }

        if let Some(source) = lockfile_npm_metadata_source(lockfile.as_ref(), &lookup_name, client)
        {
            upgradeable_deps.push(UpgradeDependency {
                name,
                lookup_name,
                range,
                manifest_value,
                is_dev,
                lookup: MetadataLookup::Npm(source),
                manifest_spec,
            });
            continue;
        }

        skipped_private.push(name);
    }
    skipped_private.sort();

    if !requested_packages.is_empty() && !skipped_private.is_empty() {
        return Err(LpmError::Script(format!(
            "cannot upgrade requested package(s) without a recorded public npm or LPM-registry source: {}. Run `lpm install` to record sources in lpm.lock, then re-run.",
            skipped_private.join(", ")
        )));
    }

    if !json_output {
        install_ui::phase("Checking dependencies for newer matching versions");
    }

    // Fetch all metadata concurrently
    let fetch_futures: Vec<_> = upgradeable_deps
        .iter()
        .map(|dep| async move {
            let result = fetch_metadata(client, &dep.lookup, &dep.lookup_name).await;
            (dep, result)
        })
        .collect();
    let fetch_results = futures::future::join_all(fetch_futures).await;

    let mut candidates: Vec<EnrichedCandidate> = Vec::new();
    let mut fetch_errors: usize = 0;

    for (dep, metadata_result) in fetch_results {
        let metadata = match metadata_result {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    "failed to fetch metadata for {} via {}: {}",
                    dep.name,
                    dep.lookup_name,
                    e
                );
                fetch_errors += 1;
                continue;
            }
        };

        let latest = match crate::release_age_selection::latest_allowed_version(
            &metadata,
            &release_age_policy,
        ) {
            Some(v) => v,
            None => continue,
        };

        if !is_valid_version_string(&latest) {
            tracing::warn!(
                "skipping {}: registry returned invalid version string {:?}",
                dep.name,
                latest
            );
            continue;
        }

        let available_versions =
            crate::release_age_selection::allowed_version_strings(&metadata, &release_age_policy);

        let installed_ver = lockfile.as_ref().and_then(|lf| {
            lf.find_package(&dep.lookup_name)
                .map(|p| p.version.as_str())
        });

        // Build enrichment data from the target version's metadata.
        // We use the LATEST version's metadata for enrichment since that's
        // what the user will get post-upgrade.
        let enrich = |target_version: &str| -> (bool, PeerImpact, Option<PatchInvalidation>) {
            let meta = metadata.version(target_version);
            let has_scripts = meta.is_some_and(upgrade_engine::target_has_install_scripts);
            let peer_deps = meta
                .map(|m| m.peer_dependencies.clone())
                .unwrap_or_default();
            let peer_impact = upgrade_engine::compute_peer_impact(&peer_deps, lockfile.as_ref());
            let from_ver = installed_ver.unwrap_or("0.0.0");
            let patch_inv = upgrade_engine::detect_patch_invalidation(
                &patched_deps,
                &dep.lookup_name,
                from_ver,
                target_version,
            );
            (has_scripts, peer_impact, patch_inv)
        };

        match mode {
            ResolvedMode::NonInteractive => {
                // Today's behavior: single candidate per dep
                let (target_version, new_range) =
                    compute_upgrade(&dep.range, &latest, &available_versions, major);
                let target_version = match target_version {
                    Some(v) => v,
                    None => continue,
                };

                let should_skip = if let Some(installed) = installed_ver {
                    installed == target_version
                } else {
                    dep.range == new_range
                };
                if should_skip {
                    continue;
                }

                let from =
                    installed_ver.map_or_else(|| version_from_range(&dep.range), str::to_string);
                let semver_class = upgrade_engine::classify_semver_change(&from, &target_version);
                let (has_scripts, peer_impact, patch_inv) = enrich(&target_version);
                let new_manifest_value = dep.manifest_spec.render_new_value(&new_range);

                candidates.push(EnrichedCandidate {
                    name: dep.name.clone(),
                    from,
                    current_range: dep.manifest_value.clone(),
                    new_range: new_manifest_value,
                    to: target_version,
                    is_dev: dep.is_dev,
                    target_kind: if major {
                        TargetKind::AbsoluteLatest
                    } else {
                        TargetKind::WithinMajor
                    },
                    semver_class,
                    has_install_scripts: has_scripts,
                    peer_impact,
                    patch_invalidation: patch_inv,
                });
            }
            ResolvedMode::Interactive => {
                // Dual-row mode: compute within-major AND absolute-latest.
                let (within_target, within_range) =
                    compute_upgrade(&dep.range, &latest, &available_versions, false);
                let (abs_target, abs_range) =
                    compute_upgrade(&dep.range, &latest, &available_versions, true);

                let from =
                    installed_ver.map_or_else(|| version_from_range(&dep.range), str::to_string);

                // Emit within-major row if it's a real upgrade
                if let Some(ref wt) = within_target {
                    let should_skip = if let Some(installed) = installed_ver {
                        installed == wt.as_str()
                    } else {
                        dep.range == within_range
                    };
                    if !should_skip {
                        let semver_class = upgrade_engine::classify_semver_change(&from, wt);
                        let (has_scripts, peer_impact, patch_inv) = enrich(wt);
                        let new_manifest_value = dep.manifest_spec.render_new_value(&within_range);
                        candidates.push(EnrichedCandidate {
                            name: dep.name.clone(),
                            from: from.clone(),
                            current_range: dep.manifest_value.clone(),
                            new_range: new_manifest_value,
                            to: wt.clone(),
                            is_dev: dep.is_dev,
                            target_kind: TargetKind::WithinMajor,
                            semver_class,
                            has_install_scripts: has_scripts,
                            peer_impact,
                            patch_invalidation: patch_inv,
                        });
                    }
                }

                // Emit absolute-latest row if it differs from the within-major
                if let Some(ref at) = abs_target {
                    let same_as_within = within_target.as_deref() == Some(at.as_str());
                    if !same_as_within {
                        let should_skip = if let Some(installed) = installed_ver {
                            installed == at.as_str()
                        } else {
                            dep.range == abs_range
                        };
                        if !should_skip {
                            let semver_class = upgrade_engine::classify_semver_change(&from, at);
                            let (has_scripts, peer_impact, patch_inv) = enrich(at);
                            let new_manifest_value = dep.manifest_spec.render_new_value(&abs_range);
                            candidates.push(EnrichedCandidate {
                                name: dep.name.clone(),
                                from: from.clone(),
                                current_range: dep.manifest_value.clone(),
                                new_range: new_manifest_value,
                                to: at.clone(),
                                is_dev: dep.is_dev,
                                target_kind: TargetKind::AbsoluteLatest,
                                semver_class,
                                has_install_scripts: has_scripts,
                                peer_impact,
                                patch_invalidation: patch_inv,
                            });
                        }
                    }
                }
            }
        }
    }

    // Sort for deterministic output
    candidates.sort_by(|a, b| {
        a.name.cmp(&b.name).then(a.to.cmp(&b.to)) // within-major first since it's lower
    });

    // Warn about fetch errors
    if fetch_errors > 0 && !json_output {
        install_ui::warn_untrusted(&format!(
            "Could not check {} package(s) (network errors)",
            fetch_errors
        ));
    }

    if candidates.is_empty() {
        if json_output {
            let mut json = serde_json::json!({
                "success": true,
                "dry_run": dry_run,
                "upgraded": 0,
                "packages": [],
                "fetch_errors": fetch_errors,
            });
            attach_skipped_private(&mut json, &skipped_private);
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            let message = if requested_packages.is_empty() {
                "All checked package.json dependencies are up to date"
            } else {
                "All requested package.json dependencies are up to date"
            };
            install_ui::done_untrusted(message);
            warn_skipped_private(&skipped_private);
        }
        return Ok(());
    }

    // ── Selection ───────────────────────────────────────────────────

    let selected: Vec<EnrichedCandidate> = match mode {
        ResolvedMode::NonInteractive => candidates.clone(),
        ResolvedMode::Interactive => {
            let selection = select_candidates_interactively(&candidates)?;
            if selection.is_empty() {
                install_ui::phase("No packages selected. package.json is unchanged.");
                return Ok(());
            }
            selection
        }
    };

    // Deduplicate: if both within-major and absolute-latest rows were
    // selected for the same package, take the highest target version.
    let deduped = deduplicate_by_highest_target(&selected);

    // ── Display + dry-run gate ──────────────────────────────────────

    if json_output {
        let pkgs: Vec<serde_json::Value> = deduped.iter().map(candidate_to_json).collect();
        let mut json = serde_json::json!({
            "success": true,
            "dry_run": dry_run,
            "upgraded": deduped.len(),
            "packages": pkgs,
            "fetch_errors": fetch_errors,
        });
        attach_skipped_private(&mut json, &skipped_private);
        println!(
            "{}",
            serde_json::to_string_pretty(&json).unwrap_or_default()
        );
        if dry_run {
            return Ok(());
        }
    } else {
        install_ui::phase_untrusted(&format!(
            "Upgrading {} {}",
            deduped.len(),
            install_ui::packages_word(deduped.len())
        ));
        for u in &deduped {
            let dev_tag = if u.is_dev { " (dev)" } else { "" };
            let glyph = format_upgrade_glyph(u.semver_class);
            let safe_name = lpm_common::sanitize_terminal_inline(&u.name);
            let safe_from = lpm_common::sanitize_terminal_inline(&u.from);
            let safe_to = lpm_common::sanitize_terminal_inline(&u.to);
            let name = format!("{safe_name:<24}").bold();
            let from = format!("{safe_from:>8}").dimmed();
            let arrow = "→".dimmed();
            let to = format!("{safe_to:<8}").yellow();
            let class_label = format_class_label(u.semver_class);
            let hint = format_candidate_hint(u);
            let hint_suffix = if hint.is_empty() {
                String::new()
            } else {
                format!("  {}", hint.dimmed())
            };
            eprintln!(
                "{glyph} {name} {from} {arrow} {to} {class_label}{}{}",
                dev_tag.dimmed(),
                hint_suffix,
            );
        }

        if dry_run {
            install_ui::done_untrusted(&format!(
                "Done · would upgrade {} {} (dry run)",
                deduped.len(),
                install_ui::packages_word(deduped.len())
            ));
            warn_skipped_private(&skipped_private);
            return Ok(());
        }
    }

    // ── Mutate package.json ─────────────────────────────────────────

    apply_upgrades_to_manifest(&mut doc, &deduped)?;
    let updated_content = serde_json::to_string_pretty(&doc)
        .map_err(|e| LpmError::Script(format!("failed to serialize package.json: {e}")))?;

    let tmp_path = pkg_json_path.with_extension("json.tmp");
    let lockfile_backup = read_optional_file(&project_dir.join("lpm.lock"))?;
    let lockfile_binary_backup = read_optional_file(&project_dir.join("lpm.lockb"))?;

    std::fs::write(&tmp_path, format!("{updated_content}\n"))
        .map_err(|e| LpmError::Script(format!("failed to write temp package.json: {e}")))?;
    std::fs::rename(&tmp_path, &pkg_json_path)
        .map_err(|e| LpmError::Script(format!("failed to rename temp package.json: {e}")))?;

    // ── Run install with backup-and-restore ──────────────────────────

    if !json_output {
        install_ui::phase("Installing upgraded dependencies");
    }

    remove_optional_file(&project_dir.join("lpm.lock"))?;
    remove_optional_file(&project_dir.join("lpm.lockb"))?;

    let install_result = crate::commands::install::run_with_options(
        client,
        project_dir,
        json_output,
        false, // offline
        crate::commands::install::FrozenLockfileMode::Never,
        false, // force
        false, // allow_new
        false, // strict_integrity
        false, // no_engine_strict
        None,  // strict_peer_dependencies_override
        None,  // linker_override
        crate::lpm_skills_config::LpmSkillsPreference::Config,
        false, // no_editor_setup
        false, // no_security_summary
        false, // auto_build
        None,  // target_set
        None,  // direct_versions_out
        None,  // requested_add_count: upgrade is not an add-path install
        None,  // script_policy_override: `lpm upgrade` does not expose policy flags
        None,  // advisor_override: `lpm upgrade` does not expose `--advisor`
        None,  // min_release_age_override: `lpm upgrade` uses the chain
        &[],
        crate::provenance_fetch::DriftIgnorePolicy::default(), // drift-ignore: `lpm upgrade` enforces drift
        // `lpm upgrade` does not surface its own
        // `--unverified-provenance{,-all}` flags; the verifier honors
        // the operator-persistent posture chain (env + `[sigstore]
        // verify` config) so an operator who set warn / off via
        // `lpm install` gets the same posture here.
        crate::provenance_fetch::VerifyPolicy::resolve_no_cli(),
        crate::commands::install::InstallOmitPolicy::default(),
        // `lpm upgrade` does not
        // surface its own sandbox-mode flags. The chain inside
        // `rebuild::run` still walks env / config / default, so
        // users who configured strict persistently still get it.
        false, // strict_sandbox
        false, // no_sandbox
        false, // verbose: internal pipeline, no user-facing Done footer
        false, // audit_after_install: internal pipeline never runs audit
        false, // timing: upgrade does not expose install's --timing flag
        &[],
    )
    .await;

    if let Err(e) = install_result {
        if let Err(restore_err) = std::fs::write(&pkg_json_path, &original_content) {
            tracing::error!(
                "failed to restore package.json after install failure: {}",
                restore_err
            );
        } else if !json_output {
            install_ui::warn("install failed — restored original package.json");
        }

        if let Err(restore_err) =
            restore_optional_file(&project_dir.join("lpm.lock"), &lockfile_backup)
        {
            tracing::error!(
                "failed to restore lpm.lock after install failure: {}",
                restore_err
            );
        }
        if let Err(restore_err) =
            restore_optional_file(&project_dir.join("lpm.lockb"), &lockfile_binary_backup)
        {
            tracing::error!(
                "failed to restore lpm.lockb after install failure: {}",
                restore_err
            );
        }
        if let Err(invalidate_err) =
            remove_optional_file(&project_dir.join(".lpm").join("install-hash"))
        {
            tracing::error!(
                "failed to invalidate .lpm/install-hash after install failure: {}",
                invalidate_err
            );
        }
        return Err(e);
    }

    if !json_output {
        install_ui::done("Updated package.json, lpm.lock, node_modules");
        install_ui::done_untrusted(&format!(
            "Done · upgraded {} {} in {}",
            deduped.len(),
            install_ui::packages_word(deduped.len()),
            install_ui::format_duration(started_at.elapsed())
        ));
        warn_skipped_private(&skipped_private);
    }

    Ok(())
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>, LpmError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(LpmError::Script(format!(
            "failed to read {}: {err}",
            path.display()
        ))),
    }
}

fn remove_optional_file(path: &Path) -> Result<(), LpmError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(LpmError::Script(format!(
            "failed to remove {}: {err}",
            path.display()
        ))),
    }
}

fn restore_optional_file(path: &Path, backup: &Option<Vec<u8>>) -> std::io::Result<()> {
    match backup {
        Some(bytes) => std::fs::write(path, bytes),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        },
    }
}

async fn fetch_metadata(
    client: &RegistryClient,
    lookup: &MetadataLookup,
    name: &str,
) -> Result<PackageMetadata, LpmError> {
    match lookup {
        MetadataLookup::Lpm(pkg_name) => client.get_package_metadata(pkg_name).await,
        MetadataLookup::Npm(NpmMetadataSource::PublicNpm) => {
            client.get_npm_package_metadata(name).await
        }
        MetadataLookup::Npm(NpmMetadataSource::ConfiguredRegistry) => {
            client.get_npm_package_metadata_proxy_only(name).await
        }
    }
}

fn attach_skipped_private(json: &mut serde_json::Value, skipped_private: &[String]) {
    if skipped_private.is_empty() {
        return;
    }

    json.as_object_mut()
        .unwrap()
        .insert("skipped_private".into(), serde_json::json!(skipped_private));
    json.as_object_mut().unwrap().insert(
        "skipped_private_reason".into(),
        serde_json::json!(
            "Packages without a recorded public npm or LPM-registry source were skipped to avoid leaking private names to registry.npmjs.org. Run `lpm install` to resolve sources, then re-run."
        ),
    );
}

fn warn_skipped_private(skipped_private: &[String]) {
    if skipped_private.is_empty() {
        return;
    }

    let names = skipped_private
        .iter()
        .map(|name| lpm_common::sanitize_terminal_inline(name).into_owned())
        .collect::<Vec<_>>();
    install_ui::warn_untrusted(&format!(
        "skipped {} package(s) without a recorded public npm or LPM-registry source to avoid leaking private names to registry.npmjs.org: {}",
        skipped_private.len(),
        names.join(", "),
    ));
    install_ui::phase("run `lpm install` first to record sources in lpm.lock, then re-run.");
}

// ── Interactive multiselect ─────────────────────────────────────────

fn select_candidates_interactively(
    candidates: &[EnrichedCandidate],
) -> Result<Vec<EnrichedCandidate>, LpmError> {
    let pkg_count = {
        let mut names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        names.dedup();
        names.len()
    };
    let target_count = candidates.len();
    if target_count == pkg_count {
        install_ui::phase_untrusted(&format!("{pkg_count} package(s) can be upgraded."));
    } else {
        install_ui::phase_untrusted(&format!(
            "{target_count} upgrade targets across {pkg_count} packages."
        ));
    }

    let mut ms =
        cliclack::multiselect("Select packages to upgrade  (space=toggle  a=all  enter=confirm)");

    let initial_indices: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            upgrade_engine::default_pre_check(
                c.semver_class,
                c.has_install_scripts,
                &c.peer_impact,
                c.patch_invalidation.as_ref(),
            )
        })
        .map(|(i, _)| i)
        .collect();

    for (i, c) in candidates.iter().enumerate() {
        let label = format_candidate_row_for_tui(c);
        let hint = format_candidate_hint(c);
        ms = ms.item(i, label, hint);
    }
    ms = ms.initial_values(initial_indices);

    let chosen_indices: Vec<usize> = ms.interact().map_err(prompt_err)?;

    let selected: Vec<EnrichedCandidate> = chosen_indices
        .into_iter()
        .filter_map(|i| candidates.get(i).cloned())
        .collect();
    Ok(selected)
}

// ── Deduplication ───────────────────────────────────────────────────

/// When both the within-major and absolute-latest rows are selected for
/// the same package, keep only the one with the higher target version.
fn deduplicate_by_highest_target(selected: &[EnrichedCandidate]) -> Vec<EnrichedCandidate> {
    let mut best: HashMap<String, EnrichedCandidate> = HashMap::new();
    for c in selected {
        let key = format!("{}|{}", c.name, c.current_range);
        let replace = match best.get(&key) {
            None => true,
            Some(existing) => {
                // Higher version wins. If both parse, compare structurally;
                // if either fails to parse, compare lexicographically.
                match (Version::parse(&c.to), Version::parse(&existing.to)) {
                    (Ok(a), Ok(b)) => a > b,
                    _ => c.to > existing.to,
                }
            }
        };
        if replace {
            best.insert(key, c.clone());
        }
    }
    let mut result: Vec<EnrichedCandidate> = best.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

// ── Formatting helpers ──────────────────────────────────────────────

fn format_candidate_row_for_tui(c: &EnrichedCandidate) -> String {
    let dev_tag = if c.is_dev { " (dev)" } else { "" };
    let class_label = format_class_label(c.semver_class);
    let kind_tag = match c.target_kind {
        TargetKind::AbsoluteLatest => " (latest)",
        TargetKind::WithinMajor => "",
    };
    let name = lpm_common::sanitize_terminal_inline(&c.name);
    let from = lpm_common::sanitize_terminal_inline(&c.from);
    let to = lpm_common::sanitize_terminal_inline(&c.to);
    format!(
        "{:<40} {} → {} {}{}{}",
        name, from, to, class_label, kind_tag, dev_tag,
    )
}

fn format_candidate_hint(c: &EnrichedCandidate) -> String {
    let mut parts: Vec<String> = Vec::new();

    if c.has_install_scripts {
        parts.push("[!] install scripts (will need approve-scripts)".into());
    }

    if !c.peer_impact.ok {
        let mut peer_parts: Vec<String> = Vec::new();
        for v in &c.peer_impact.violations {
            peer_parts.push(format!(
                "{}={}≠{}",
                lpm_common::sanitize_terminal_inline(&v.name),
                lpm_common::sanitize_terminal_inline(&v.have),
                lpm_common::sanitize_terminal_inline(&v.want)
            ));
        }
        for m in &c.peer_impact.missing {
            peer_parts.push(format!(
                "{} missing",
                lpm_common::sanitize_terminal_inline(m)
            ));
        }
        if !peer_parts.is_empty() {
            parts.push(format!(
                "peer: {} (current lockfile)",
                peer_parts.join(", ")
            ));
        }
    }

    if let Some(ref inv) = c.patch_invalidation {
        parts.push(format!(
            "orphans patch {}",
            lpm_common::sanitize_terminal_inline(&inv.key)
        ));
    }

    parts.join("  •  ")
}

fn format_class_label(class: SemverClass) -> String {
    match class {
        SemverClass::Patch => "patch".green(),
        SemverClass::Minor => "minor".yellow(),
        SemverClass::Major => "MAJOR".red(),
        SemverClass::Prerelease => "pre".dimmed(),
        SemverClass::Unknown => "?".dimmed(),
    }
}

fn format_upgrade_glyph(class: SemverClass) -> String {
    match class {
        SemverClass::Patch => "↑".green(),
        SemverClass::Minor => "↑".yellow(),
        SemverClass::Major => "↑".red(),
        SemverClass::Prerelease | SemverClass::Unknown => "↑".dimmed(),
    }
}

fn candidate_to_json(c: &EnrichedCandidate) -> serde_json::Value {
    serde_json::json!({
        "name": c.name,
        "from": c.from,
        "to": c.to,
        "new_range": c.new_range,
        "is_dev": c.is_dev,
        "semver_class": c.semver_class,
        "has_install_scripts": c.has_install_scripts,
        "peer_impact": c.peer_impact,
        "patch_invalidation": c.patch_invalidation,
    })
}

fn apply_upgrades_to_manifest(
    doc: &mut serde_json::Value,
    upgrades: &[EnrichedCandidate],
) -> Result<(), LpmError> {
    for upgrade in upgrades {
        let dep_key = if upgrade.is_dev {
            "devDependencies"
        } else {
            "dependencies"
        };

        let deps = doc
            .get_mut(dep_key)
            .and_then(|value| value.as_object_mut())
            .ok_or_else(|| {
                LpmError::Script(format!(
                    "package.json is missing `{dep_key}` while upgrading {}",
                    upgrade.name
                ))
            })?;

        match deps.get_mut(&upgrade.name) {
            Some(serde_json::Value::String(current)) => {
                if current != &upgrade.current_range {
                    return Err(LpmError::Script(format!(
                        "package.json drifted before upgrade could write {}: expected `{}`, found `{}`",
                        upgrade.name, upgrade.current_range, current
                    )));
                }
                *current = upgrade.new_range.clone();
            }
            _ => {
                return Err(LpmError::Script(format!(
                    "package.json is missing string dependency entry `{}` in `{dep_key}`",
                    upgrade.name
                )));
            }
        }
    }

    Ok(())
}

// ── Preserved helpers from the original upgrade.rs ──────────────────

/// Extract dependencies and devDependencies from a parsed JSON Value.
fn extract_deps_from_value(doc: &serde_json::Value) -> Vec<(String, String, bool)> {
    let mut deps = Vec::new();
    if let Some(obj) = doc.get("dependencies").and_then(|d| d.as_object()) {
        for (k, v) in obj {
            if let Some(range) = v.as_str() {
                deps.push((k.clone(), range.to_string(), false));
            }
        }
    }
    if let Some(obj) = doc.get("devDependencies").and_then(|d| d.as_object()) {
        for (k, v) in obj {
            if let Some(range) = v.as_str() {
                deps.push((k.clone(), range.to_string(), true));
            }
        }
    }
    deps
}

fn filter_requested_deps(
    deps: Vec<(String, String, bool)>,
    requested_packages: &[String],
) -> Result<Vec<(String, String, bool)>, LpmError> {
    if requested_packages.is_empty() {
        return Ok(deps);
    }

    let requested = requested_packages.iter().cloned().collect::<BTreeSet<_>>();
    let available = deps
        .iter()
        .map(|(name, _, _)| name.clone())
        .collect::<BTreeSet<_>>();
    let missing = requested
        .difference(&available)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(LpmError::Script(format!(
            "package(s) not found in package.json dependencies or devDependencies: {}",
            missing.join(", ")
        )));
    }

    Ok(deps
        .into_iter()
        .filter(|(name, _, _)| requested.contains(name))
        .collect())
}

/// Compute the upgrade target version and new range.
///
/// In default (non-major) mode, stays within the current major version.
/// In major mode, uses the absolute latest.
fn compute_upgrade(
    current_range: &str,
    latest: &str,
    available_versions: &[String],
    major: bool,
) -> (Option<String>, String) {
    let prefix = if current_range.starts_with('^') {
        "^"
    } else if current_range.starts_with('~') {
        "~"
    } else {
        ""
    };

    if major {
        let new_range = format!("{prefix}{latest}");
        return (Some(latest.to_string()), new_range);
    }

    let range_body = current_range.trim_start_matches(['^', '~']);
    let current_major = range_body
        .split('.')
        .next()
        .and_then(|s| s.parse::<u64>().ok());

    let current_major = match current_major {
        Some(m) => m,
        None => {
            let new_range = format!("{prefix}{latest}");
            return (Some(latest.to_string()), new_range);
        }
    };

    let mut same_major_versions: Vec<Version> = available_versions
        .iter()
        .filter_map(|v| Version::parse(v).ok())
        .filter(|v| v.major() == current_major && !v.is_prerelease())
        .collect();

    if same_major_versions.is_empty() {
        return (None, current_range.to_string());
    }

    lpm_semver::sort_versions(&mut same_major_versions);
    let best = same_major_versions.last().unwrap();
    let best_str = best.to_string();
    let new_range = format!("{prefix}{best_str}");

    (Some(best_str), new_range)
}

/// Extract a best-effort version string from a range like `"^1.2.0"`.
/// Strips `^`, `~`, `>=`, `=` prefixes and returns the body. If the
/// body doesn't look like a version (e.g., `"*"`), returns it as-is
/// — the caller's `classify_semver_change` will return `Unknown`.
///
/// When no lockfile exists, `installed_ver` is `None` and the old code
/// used `"?"` as the "from" version, which
/// `classify_semver_change` can't parse → `Unknown` → patches/minors
/// don't get pre-checked. This helper extracts a real version from
/// the manifest range so classification works correctly even without
/// a lockfile.
fn version_from_range(range: &str) -> String {
    range
        .trim_start_matches(['^', '~', '>', '<', '='])
        .trim()
        .to_string()
}

fn is_valid_version_string(v: &str) -> bool {
    if v.is_empty() {
        return false;
    }
    v.chars()
        .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '+')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_requested_deps_keeps_only_named_manifest_dependencies() {
        let deps = vec![
            ("zod".to_string(), "^3.0.0".to_string(), false),
            ("typescript".to_string(), "^5.0.0".to_string(), true),
            ("react".to_string(), "^18.0.0".to_string(), false),
        ];

        let filtered = filter_requested_deps(deps, &["typescript".to_string()]).unwrap();

        assert_eq!(
            filtered,
            vec![("typescript".to_string(), "^5.0.0".to_string(), true)]
        );
    }

    #[test]
    fn filter_requested_deps_errors_when_package_is_not_manifest_dependency() {
        let deps = vec![("zod".to_string(), "^3.0.0".to_string(), false)];

        let err = filter_requested_deps(deps, &["react".to_string()]).unwrap_err();

        assert!(
            err.to_string().contains("react"),
            "missing package error should name the requested dependency: {err}"
        );
    }

    #[test]
    fn manifest_dependency_spec_parses_unscoped_npm_alias() {
        let (spec, range) =
            ManifestDependencySpec::from_manifest_value("strip-ansi-cjs", "npm:strip-ansi@^6")
                .unwrap();

        assert!(matches!(
            &spec,
            ManifestDependencySpec::NpmAlias { target } if target == "strip-ansi"
        ));
        assert_eq!(range, "^6");
        assert_eq!(spec.render_new_value("^6.1.0"), "npm:strip-ansi@^6.1.0");
    }

    #[test]
    fn manifest_dependency_spec_parses_scoped_npm_alias() {
        let (spec, range) =
            ManifestDependencySpec::from_manifest_value("node-types", "npm:@types/node@^20")
                .unwrap();

        assert!(matches!(
            &spec,
            ManifestDependencySpec::NpmAlias { target } if target == "@types/node"
        ));
        assert_eq!(range, "^20");
        assert_eq!(spec.render_new_value("^20.1.0"), "npm:@types/node@^20.1.0");
    }

    // ── compute_upgrade (preserved from original) ───────────────────

    #[test]
    fn default_mode_stays_within_major() {
        let available = vec!["1.2.0".into(), "1.5.0".into(), "2.0.0".into()];
        let (target, new_range) = compute_upgrade("^1.2.0", "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
        assert_eq!(new_range, "^1.5.0");
    }

    #[test]
    fn major_mode_jumps_to_latest() {
        let available = vec!["1.2.0".into(), "1.5.0".into(), "2.0.0".into()];
        let (target, new_range) = compute_upgrade("^1.2.0", "2.0.0", &available, true);
        assert_eq!(target, Some("2.0.0".to_string()));
        assert_eq!(new_range, "^2.0.0");
    }

    #[test]
    fn default_mode_same_major_as_latest() {
        let available = vec!["2.0.0".into(), "2.1.0".into(), "2.3.0".into()];
        let (target, new_range) = compute_upgrade("^2.0.0", "2.3.0", &available, false);
        assert_eq!(target, Some("2.3.0".to_string()));
        assert_eq!(new_range, "^2.3.0");
    }

    #[test]
    fn default_mode_tilde_prefix_preserved() {
        let available = vec!["1.2.0".into(), "1.5.0".into(), "2.0.0".into()];
        let (target, new_range) = compute_upgrade("~1.2.0", "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
        assert_eq!(new_range, "~1.5.0");
    }

    #[test]
    fn default_mode_no_prefix() {
        let available = vec!["1.2.0".into(), "1.5.0".into(), "2.0.0".into()];
        let (target, new_range) = compute_upgrade("1.2.0", "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
        assert_eq!(new_range, "1.5.0");
    }

    #[test]
    fn default_mode_skips_prereleases() {
        let available = vec![
            "1.2.0".into(),
            "1.6.0-beta.1".into(),
            "1.5.0".into(),
            "2.0.0".into(),
        ];
        let (target, _) = compute_upgrade("^1.2.0", "2.0.0", &available, false);
        assert_eq!(target, Some("1.5.0".to_string()));
    }

    // ── resolve_mode ────────────────────────────────────────────────

    #[test]
    fn resolve_mode_default_tty_is_interactive() {
        assert_eq!(
            resolve_mode(false, false, false, true).unwrap(),
            ResolvedMode::Interactive
        );
    }

    #[test]
    fn resolve_mode_default_no_tty_is_non_interactive() {
        assert_eq!(
            resolve_mode(false, false, false, false).unwrap(),
            ResolvedMode::NonInteractive
        );
    }

    #[test]
    fn resolve_mode_yes_forces_non_interactive_in_tty() {
        assert_eq!(
            resolve_mode(false, true, false, true).unwrap(),
            ResolvedMode::NonInteractive
        );
    }

    #[test]
    fn resolve_mode_interactive_forces_interactive_no_tty() {
        assert_eq!(
            resolve_mode(true, false, false, false).unwrap(),
            ResolvedMode::Interactive
        );
    }

    #[test]
    fn resolve_mode_json_forces_non_interactive() {
        assert_eq!(
            resolve_mode(false, false, true, true).unwrap(),
            ResolvedMode::NonInteractive
        );
    }

    #[test]
    fn resolve_mode_interactive_and_yes_is_hard_error() {
        assert!(resolve_mode(true, true, false, true).is_err());
    }

    #[test]
    fn resolve_mode_interactive_and_json_is_hard_error() {
        assert!(resolve_mode(true, false, true, false).is_err());
    }

    #[test]
    fn validate_major_for_mode_rejects_major_in_interactive() {
        assert!(validate_major_for_mode(true, ResolvedMode::Interactive).is_err());
    }

    #[test]
    fn validate_major_for_mode_accepts_major_in_non_interactive() {
        assert!(validate_major_for_mode(true, ResolvedMode::NonInteractive).is_ok());
    }

    #[test]
    fn validate_major_for_mode_accepts_no_major_in_either() {
        assert!(validate_major_for_mode(false, ResolvedMode::Interactive).is_ok());
        assert!(validate_major_for_mode(false, ResolvedMode::NonInteractive).is_ok());
    }

    // ── formatting helpers ──────────────────────────────────────────

    fn make_candidate(
        class: SemverClass,
        has_scripts: bool,
        peer_ok: bool,
        has_patch_inv: bool,
    ) -> EnrichedCandidate {
        let peer_impact = if peer_ok {
            PeerImpact {
                ok: true,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![],
            }
        } else {
            PeerImpact {
                ok: false,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![PeerViolation {
                    name: "react".into(),
                    have: "17.0.2".into(),
                    want: "^18.0.0".into(),
                }],
            }
        };
        let patch_invalidation = if has_patch_inv {
            Some(PatchInvalidation {
                key: "lodash@4.17.20".into(),
                patch_path: "patches/lodash.patch".into(),
                from_version: "4.17.20".into(),
                to_version: "4.17.21".into(),
            })
        } else {
            None
        };
        EnrichedCandidate {
            name: "@lpm.dev/test.pkg".into(),
            from: "1.2.0".into(),
            current_range: "^1.2.0".into(),
            new_range: "^1.2.4".into(),
            to: "1.2.4".into(),
            is_dev: false,
            target_kind: TargetKind::WithinMajor,
            semver_class: class,
            has_install_scripts: has_scripts,
            peer_impact,
            patch_invalidation,
        }
    }

    #[test]
    fn format_row_includes_class_label() {
        let c = make_candidate(SemverClass::Patch, false, true, false);
        let row = format_candidate_row_for_tui(&c);
        assert!(row.contains("1.2.0"));
        assert!(row.contains("1.2.4"));
    }

    #[test]
    fn format_hint_marks_install_scripts() {
        let c = make_candidate(SemverClass::Patch, true, true, false);
        let hint = format_candidate_hint(&c);
        assert!(hint.contains("[!]"));
        assert!(hint.contains("install scripts"));
    }

    #[test]
    fn format_hint_marks_peer_violation() {
        let c = make_candidate(SemverClass::Minor, false, false, false);
        let hint = format_candidate_hint(&c);
        assert!(hint.contains("react"));
        assert!(hint.contains("current lockfile"));
    }

    #[test]
    fn format_hint_marks_patch_invalidation() {
        let c = make_candidate(SemverClass::Minor, false, true, true);
        let hint = format_candidate_hint(&c);
        assert!(hint.contains("orphans patch"));
        assert!(hint.contains("lodash@4.17.20"));
    }

    #[test]
    fn format_hint_is_empty_when_clean() {
        let c = make_candidate(SemverClass::Patch, false, true, false);
        let hint = format_candidate_hint(&c);
        assert!(hint.is_empty());
    }

    // ── Dual-row model ──────────────────────────────────────────────

    #[test]
    fn deduplicate_takes_major_when_both_selected() {
        let minor = EnrichedCandidate {
            name: "pkg".into(),
            from: "3.4.0".into(),
            current_range: "^3.4.0".into(),
            new_range: "^3.9.0".into(),
            to: "3.9.0".into(),
            is_dev: false,
            target_kind: TargetKind::WithinMajor,
            semver_class: SemverClass::Minor,
            has_install_scripts: false,
            peer_impact: PeerImpact {
                ok: true,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![],
            },
            patch_invalidation: None,
        };
        let major = EnrichedCandidate {
            to: "4.0.0".into(),
            new_range: "^4.0.0".into(),
            target_kind: TargetKind::AbsoluteLatest,
            semver_class: SemverClass::Major,
            ..minor.clone()
        };
        let deduped = deduplicate_by_highest_target(&[minor, major]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].to, "4.0.0");
    }

    #[test]
    fn deduplicate_keeps_minor_when_only_minor_selected() {
        let minor = EnrichedCandidate {
            name: "pkg".into(),
            from: "3.4.0".into(),
            current_range: "^3.4.0".into(),
            new_range: "^3.9.0".into(),
            to: "3.9.0".into(),
            is_dev: false,
            target_kind: TargetKind::WithinMajor,
            semver_class: SemverClass::Minor,
            has_install_scripts: false,
            peer_impact: PeerImpact {
                ok: true,
                basis: "current_lockfile".into(),
                missing: vec![],
                violations: vec![],
            },
            patch_invalidation: None,
        };
        let deduped = deduplicate_by_highest_target(&[minor]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].to, "3.9.0");
    }

    // ── extract_deps_from_value (preserved) ─────────────────────────

    #[test]
    fn extract_deps_from_json_value() {
        let doc: serde_json::Value = serde_json::from_str(
            r#"{"dependencies":{"foo":"^1.0.0"},"devDependencies":{"bar":"~2.0.0"}}"#,
        )
        .unwrap();
        let deps = extract_deps_from_value(&doc);
        assert_eq!(deps.len(), 2);
        assert!(
            deps.iter()
                .any(|(n, r, d)| n == "foo" && r == "^1.0.0" && !d)
        );
        assert!(
            deps.iter()
                .any(|(n, r, d)| n == "bar" && r == "~2.0.0" && *d)
        );
    }

    // ── version validation (preserved) ──────────────────────────────

    #[test]
    fn valid_version_strings() {
        assert!(is_valid_version_string("1.5.0"));
        assert!(is_valid_version_string("2.0.0-rc.1"));
        assert!(is_valid_version_string("1.0.0-beta.2"));
        assert!(is_valid_version_string("1.0.0+build.123"));
    }

    #[test]
    fn invalid_version_strings() {
        assert!(!is_valid_version_string(""));
        assert!(!is_valid_version_string("1.0.0 && rm -rf /"));
        assert!(!is_valid_version_string("1.0.0; echo pwned"));
        assert!(!is_valid_version_string("$(whoami)"));
    }

    // ── no-lockfile classification regression ─────────────
    // Bug: when no lockfile exists, `from` was "?" → classify returned
    // Unknown → patches/minors not pre-checked. Contract: the class
    // must be derived from the range body, not from "?".

    #[test]
    fn version_from_range_strips_caret() {
        assert_eq!(version_from_range("^1.2.0"), "1.2.0");
    }

    #[test]
    fn version_from_range_strips_tilde() {
        assert_eq!(version_from_range("~1.2.0"), "1.2.0");
    }

    #[test]
    fn version_from_range_strips_gte() {
        assert_eq!(version_from_range(">=1.0.0"), "1.0.0");
    }

    #[test]
    fn version_from_range_no_prefix() {
        assert_eq!(version_from_range("1.2.0"), "1.2.0");
    }

    #[test]
    fn no_lockfile_patch_upgrade_classifies_as_patch_not_unknown() {
        // The user-visible contract: ^1.0.0 → 1.0.1 is a patch upgrade
        // even when no lockfile is present. The "from" should be derived
        // from the range body "1.0.0", not "?".
        let from = version_from_range("^1.0.0");
        let class = upgrade_engine::classify_semver_change(&from, "1.0.1");
        assert_eq!(
            class,
            SemverClass::Patch,
            "no-lockfile ^1.0.0 → 1.0.1 must classify as Patch, not Unknown"
        );
        assert!(
            class.default_checked(),
            "Patch must be default-checked in the multiselect"
        );
    }

    #[test]
    fn no_lockfile_minor_upgrade_classifies_as_minor_not_unknown() {
        let from = version_from_range("^1.0.0");
        let class = upgrade_engine::classify_semver_change(&from, "1.5.0");
        assert_eq!(
            class,
            SemverClass::Minor,
            "no-lockfile ^1.0.0 → 1.5.0 must classify as Minor, not Unknown"
        );
        assert!(class.default_checked());
    }

    #[test]
    fn no_lockfile_major_upgrade_classifies_as_major() {
        let from = version_from_range("^1.0.0");
        let class = upgrade_engine::classify_semver_change(&from, "2.0.0");
        assert_eq!(class, SemverClass::Major);
        assert!(!class.default_checked());
    }
}
