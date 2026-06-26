use super::*;

/// placeholder spec written into the manifest for bare installs whose
/// final save spec depends on the resolved version. The full install
/// pipeline sees this as "any version", resolves it normally, and
/// [`finalize_packages_in_manifest`] then replaces it with the
/// resolved-version-derived spec.
///
/// This string MUST be a valid `node_semver` range so the resolver
/// accepts it. `*` is the canonical "any version" spec.
pub(super) const STAGE_PLACEHOLDER: &str = "*";

/// Outcome of staging a single dependency into the manifest.
#[derive(Debug, Clone)]
pub(crate) enum StagedKind {
    /// Stage wrote the user's verbatim explicit spec (Exact / Range /
    /// Wildcard / Workspace). Finalize is a no-op.
    Final,
    /// Stage wrote the [`STAGE_PLACEHOLDER`] for a bare install. Finalize
    /// must replace it with `decide_saved_dependency_spec(intent, resolved,
    /// flags, config)`.
    Placeholder,
    /// Stage wrote the user's dist-tag literal (`latest`, `beta`, `next`,
    /// etc.) so the resolver can honor that tag. Finalize still replaces the
    /// staged tag with the resolved save spec.
    DistTag,
    /// Stage left the manifest untouched because the dep already exists
    /// and the bare reinstall came with no rewrite-forcing flag. /// "no churn" rule. Finalize is a no-op.
    Skipped,
}

/// Per-package record produced by [`stage_packages_to_manifest`].
#[derive(Debug, Clone)]
pub(crate) struct StagedEntry {
    pub name: String,
    pub intent: crate::save_spec::UserSaveIntent,
    pub kind: StagedKind,
}

/// Snapshot of one manifest's stage step. Returned to the caller so the
/// finalize step can replay the per-entry decisions after resolution.
#[derive(Debug, Clone)]
pub(crate) struct StagedManifest {
    pub pkg_json_path: PathBuf,
    pub save_dev: bool,
    pub entries: Vec<StagedEntry>,
}

impl StagedManifest {
    /// Whether this stage produced any deferred entries that finalize must
    /// rewrite. Used by callers to skip the finalize re-read entirely when
    /// every entry was either final or skipped.
    pub fn needs_finalize(&self) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e.kind, StagedKind::Placeholder | StagedKind::DistTag))
    }
}

/// Mutate `pkg_json_path` to reflect the user's
/// install request as far as it can be determined without running the
/// resolver, and return a [`StagedManifest`] describing what still needs
/// to be patched after resolution.
///
/// Per-entry behavior:
///
/// - **Explicit user input** ([`UserSaveIntent::Exact`],
///   [`UserSaveIntent::Range`], [`UserSaveIntent::Wildcard`],
///   [`UserSaveIntent::Workspace`]) — write the verbatim string. Finalize
///   skips these.
/// - **Dist-tag** (`@latest`, `@beta`, `@next`, etc.) — write the tag
///   literal so the resolver honors that tag, mark [`StagedKind::DistTag`],
///   and let finalize rewrite it to the resolved save spec.
/// - **Bare**, dep already in target dep table, no rewrite-forcing flag —
///   leave the manifest entry alone ("no-churn" rule). Finalize skips it.
/// - **Bare**, otherwise — write [`STAGE_PLACEHOLDER`] so the resolver picks
///   up the new dep. Finalize will replace it with the final save spec once
///   the resolved version is known.
///
/// Reads → mutates → atomically rewrites the manifest in one go. Does
/// NOT touch the lockfile, the install pipeline, or any other manifest.
/// The caller is expected to wrap this call (and the install pipeline +
/// finalize) in a [`crate::manifest_tx::ManifestTransaction`] so a failed
/// install rolls the manifest bytes back to their pre-stage state.
///
/// Returns `Err(LpmError::NotFound)` if the manifest is missing,
/// `Err(LpmError::Registry)` for parse/serialize failures.
pub(crate) fn stage_packages_to_manifest(
    pkg_json_path: &Path,
    package_specs: &[String],
    save_dev: bool,
    flags: crate::save_spec::SaveFlags,
) -> Result<StagedManifest, LpmError> {
    use crate::save_spec::{UserSaveIntent, parse_user_save_intent};

    if !pkg_json_path.exists() {
        return Err(LpmError::NotFound(format!(
            "no package.json at {}",
            pkg_json_path.display()
        )));
    }

    let content = std::fs::read_to_string(pkg_json_path)?;
    let mut doc: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let dep_key = if save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };

    if doc.get(dep_key).is_none() {
        doc[dep_key] = serde_json::json!({});
    }

    let force_rewrite = flags.forces_rewrite();
    let mut entries: Vec<StagedEntry> = Vec::with_capacity(package_specs.len());
    // Track whether `doc` has been mutated. no-churn rule: when
    // every spec hits the Skipped branch, we must NOT rewrite the file —
    // re-serializing through serde_json::to_string_pretty would normalize
    // indentation and add a trailing newline, which counts as a manifest
    // mutation and trips the placeholder-survival invariant.
    let mut doc_mutated = false;

    for spec in package_specs {
        let (name, intent) = parse_user_save_intent(spec)?;

        // Tier 1: explicit user input → write verbatim, mark Final.
        let explicit_literal: Option<String> = match &intent {
            UserSaveIntent::Wildcard => Some("*".to_string()),
            UserSaveIntent::Exact(s) | UserSaveIntent::Range(s) | UserSaveIntent::Workspace(s) => {
                Some(s.clone())
            }
            UserSaveIntent::Bare | UserSaveIntent::DistTag(_) => None,
        };

        if let Some(literal) = explicit_literal {
            // No per-package "Adding X to dependencies" line — the
            // user typed the package on the command line, and the
            // `+ pkg@version` list in the Done block confirms what
            // landed in the manifest. Redundant cliclack-style chatter.
            doc[dep_key][&name] = serde_json::Value::String(literal);
            doc_mutated = true;
            entries.push(StagedEntry {
                name,
                intent,
                kind: StagedKind::Final,
            });
            continue;
        }

        if let UserSaveIntent::DistTag(tag) = &intent {
            doc[dep_key][&name] = serde_json::Value::String(tag.clone());
            doc_mutated = true;
            entries.push(StagedEntry {
                name,
                intent,
                kind: StagedKind::DistTag,
            });
            continue;
        }

        // Tier 2: bare reinstall of an existing dep with no rewrite-forcing
        // flag → skip (no-churn rule).
        //
        let is_bare_reinstall = matches!(intent, UserSaveIntent::Bare);
        let already_present = doc
            .get(dep_key)
            .and_then(|v| v.get(&name))
            .and_then(|v| v.as_str())
            .is_some();
        if is_bare_reinstall && already_present && !force_rewrite {
            // Silent: no "Refreshing X in deps" line. The Done-block
            // `+` list only fires when something actually changed —
            // a bare reinstall that keeps the existing range produces
            // no diff and therefore no list, which is the right signal.
            entries.push(StagedEntry {
                name,
                intent,
                kind: StagedKind::Skipped,
            });
            continue;
        }

        // Tier 3: bare install without an existing entry, OR an existing
        // entry that the user explicitly opted to rewrite via a flag.
        // Stage a placeholder; finalize will replace it after the resolver
        // returns the concrete version. The Done-block `+` list confirms
        // every staged package once the resolver lands a real version.
        doc[dep_key][&name] = serde_json::Value::String(STAGE_PLACEHOLDER.to_string());
        doc_mutated = true;
        entries.push(StagedEntry {
            name,
            intent,
            kind: StagedKind::Placeholder,
        });
    }

    // Only rewrite the file if we actually changed the document. The
    // all-Skipped path leaves the manifest exactly as the user wrote it,
    // including their original whitespace and trailing newline (or lack
    // thereof). This is what the row 12 no-churn workflow test asserts
    // byte-for-byte.
    if doc_mutated {
        let updated =
            serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
        lpm_common::write_file_atomic(pkg_json_path, format!("{updated}\n"))?;
    }

    Ok(StagedManifest {
        pkg_json_path: pkg_json_path.to_path_buf(),
        save_dev,
        entries,
    })
}

/// Build a `name → Version` map for
/// every direct dependency in the resolver's output. Used by the /// finalize step to look up the resolved version of placeholder-staged
/// deps without ambiguity.
///
/// Why this lives next to the install pipeline (not next to the
/// lockfile reader): the resolver's `InstallPackage` struct already
/// carries `is_direct: bool`, computed from membership in the staged
/// manifest's `dependencies` map. Reading the same information from the
/// on-disk lockfile post-install would require either a lockfile-format
/// extension (the lockfile has no direct/transitive flag) or a
/// vulnerable-to-collision flat name scan over `lockfile.packages`.
///
/// This function trusts the resolver's `is_direct` and ignores every
/// transitive entry. If the same name appears as direct more than once
/// (which would be a resolver bug, not a bug), the LAST entry
/// wins and we log a warning.
///
/// Returns an empty map if `packages` is empty or has no direct entries.
pub(super) fn collect_direct_versions(
    packages: &[InstallPackage],
) -> HashMap<String, lpm_semver::Version> {
    let mut map = HashMap::new();
    for p in packages.iter().filter(|p| p.is_direct) {
        match lpm_semver::Version::parse(&p.version) {
            Ok(v) => {
                if map.insert(p.name.clone(), v).is_some() {
                    tracing::warn!(
                        "package `{}` appears as a direct dep more than once \
                         in resolver output — last entry wins. This indicates a resolver bug.",
                        p.name
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "resolved version `{}` for direct dep `{}` did not parse \
                     as semver: {e}. Finalize will surface a missing-version error.",
                    p.version,
                    p.name
                );
            }
        }
    }
    map
}

pub(super) fn enforce_registry_integrity_policy(
    packages: &[InstallPackage],
    strict_integrity: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    for package in packages {
        if package.integrity.is_some() || !install_package_is_registry_source(package) {
            continue;
        }
        if strict_integrity {
            return Err(LpmError::Registry(format!(
                "--strict-integrity: registry package {}@{} has no dist.integrity or dist.shasum. \
                 Refusing to install an unverified registry tarball.",
                package.name, package.version
            )));
        }
        tracing::warn!(
            target: "lpm_cli::install",
            package = %package.name,
            version = %package.version,
            "registry package has no dist.integrity or dist.shasum; download will be verified only after trust-on-first-use"
        );
        if !json_output {
            output::warn(&format!(
                "registry package {}@{} has no integrity hash; pinning trust-on-first-use",
                package.name, package.version
            ));
        }
    }
    Ok(())
}

pub(super) async fn enforce_registry_signature_policy(
    client: Arc<RegistryClient>,
    route_table: &RouteTable,
    packages: &[InstallPackage],
    json_output: bool,
    allow_metadata_hydration: bool,
    timings: Option<Arc<crate::registry_signatures::RegistrySignatureTimings>>,
) -> Result<(), LpmError> {
    let inputs = registry_signature_inputs_from_install_packages(packages);
    if inputs.is_empty() {
        return Ok(());
    }

    let report = crate::registry_signatures::verify_packages_with_timings(
        client,
        route_table.clone(),
        inputs,
        allow_metadata_hydration,
        timings,
    )
    .await;

    if report.has_failures() {
        if !json_output {
            install_ui::warn(&format!(
                "Registry signatures · {} verified · {} not verified",
                report.verified(),
                report.not_verified()
            ));
            for package in report.not_verified_packages().take(10) {
                let reason = package
                    .reason
                    .as_ref()
                    .map_or_else(|| "not verified".to_string(), |reason| reason.human());
                install_ui::detail(&format!("  {}  {}", package.package_id().yellow(), reason));
            }
        }
        return Err(LpmError::Registry(registry_signature_failure_message(
            &report,
        )));
    }

    if !json_output {
        install_ui::done(&format!(
            "Registry signatures verified · {} verified",
            report.verified()
        ));
    }
    Ok(())
}

pub(super) fn registry_signature_failure_message(
    report: &crate::registry_signatures::RegistrySignatureReport,
) -> String {
    let sample = report
        .not_verified_packages()
        .take(5)
        .map(|package| {
            let reason = package
                .reason
                .as_ref()
                .map_or_else(|| "not verified".to_string(), |reason| reason.human());
            format!("{} ({reason})", package.package_id())
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "registry signature verification failed for {} package(s): {}",
        report.not_verified(),
        sample
    )
}

pub(super) fn registry_signature_inputs_from_install_packages(
    packages: &[InstallPackage],
) -> Vec<crate::registry_signatures::RegistrySignatureInput> {
    packages
        .iter()
        .map(
            |package| crate::registry_signatures::RegistrySignatureInput {
                name: package.name.clone(),
                version: package.version.clone(),
                source: Some(package.source.clone()),
                integrity: package.integrity.clone(),
                signatures: package.registry_signatures.clone(),
                published_at: package.registry_published_at.clone(),
            },
        )
        .collect()
}

pub(super) fn lockfile_registry_signatures(
    signatures: &[lpm_registry::RegistrySignature],
) -> Vec<lpm_lockfile::LockedRegistrySignature> {
    signatures
        .iter()
        .map(|signature| lpm_lockfile::LockedRegistrySignature {
            keyid: signature.keyid.clone(),
            sig: signature.sig.clone(),
        })
        .collect()
}

pub(super) fn install_registry_signatures(
    signatures: &[lpm_lockfile::LockedRegistrySignature],
) -> Vec<lpm_registry::RegistrySignature> {
    signatures
        .iter()
        .map(|signature| lpm_registry::RegistrySignature {
            keyid: signature.keyid.clone(),
            sig: signature.sig.clone(),
        })
        .collect()
}

pub(super) fn install_package_is_registry_source(package: &InstallPackage) -> bool {
    matches!(
        package.source_kind(),
        Ok(lpm_lockfile::Source::Registry { .. })
    )
}

pub(super) fn install_package_is_local_source(package: &InstallPackage) -> bool {
    matches!(
        package.source_kind(),
        Ok(lpm_lockfile::Source::Directory { .. }) | Ok(lpm_lockfile::Source::Link { .. })
    )
}

/// Replay the stage decisions against the
/// current manifest using the resolver's output, replacing any
/// deferred entries with the final save spec computed by
/// [`crate::save_spec::decide_saved_dependency_spec`].
///
/// `resolved_versions` maps direct-dep names → the concrete version
/// the resolver picked. Deferred entries missing from this map are treated
/// as "the resolver dropped them", which is a hard error: the install
/// pipeline succeeded but failed to resolve a top-level dep, which would
/// silently leave a provisional spec in the manifest. Better to surface it.
///
/// Reads the manifest fresh from disk so any unrelated edits the install
/// pipeline made (it doesn't make any today, but this future-proofs us)
/// are preserved. Atomic rewrite, same pretty-print conventions as stage.
///
/// Skips entirely if [`StagedManifest::needs_finalize`] is `false` — nothing
/// to do, and we avoid the read/write round-trip.
#[cfg(test)]
pub(crate) fn finalize_packages_in_manifest(
    staged: &StagedManifest,
    resolved_versions: &HashMap<String, lpm_semver::Version>,
    flags: crate::save_spec::SaveFlags,
    config: crate::save_spec::SaveConfig,
) -> Result<(), LpmError> {
    finalize_packages_in_manifest_with_catalog_policy(
        staged,
        resolved_versions,
        flags,
        config,
        &CatalogSavePolicy::manual(),
    )
}

pub(super) fn finalize_packages_in_manifest_with_catalog_policy(
    staged: &StagedManifest,
    resolved_versions: &HashMap<String, lpm_semver::Version>,
    flags: crate::save_spec::SaveFlags,
    config: crate::save_spec::SaveConfig,
    catalog_policy: &CatalogSavePolicy,
) -> Result<(), LpmError> {
    if !staged.needs_finalize() && !catalog_policy.can_rewrite_manifest() {
        return Ok(());
    }

    let content = std::fs::read_to_string(&staged.pkg_json_path)?;
    let mut doc: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let dep_key = if staged.save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };
    let mut doc_mutated = false;

    for entry in &staged.entries {
        let resolved = resolved_versions.get(&entry.name);

        if let Some(catalog_name) = catalog_policy.forced_catalog.as_deref() {
            let catalog_range = catalog_policy.catalog_entry(catalog_name, &entry.name)?;
            let resolved = resolved.ok_or_else(|| {
                LpmError::Registry(format!(
                    "{}: resolver did not report a concrete version for `{}`",
                    forced_catalog_flag(catalog_name),
                    entry.name
                ))
            })?;
            if catalog_range_matches_resolved(&entry.name, catalog_range, resolved)? {
                let catalog_ref = catalog_reference(catalog_name);
                if doc[dep_key][&entry.name].as_str() != Some(catalog_ref.as_str()) {
                    doc[dep_key][&entry.name] = serde_json::Value::String(catalog_ref);
                    doc_mutated = true;
                }
                continue;
            }

            let requested_spec = catalog_mode_requested_spec(&entry.intent, resolved);
            return Err(forced_catalog_mismatch_error(
                catalog_name,
                &entry.name,
                &requested_spec,
                catalog_range,
            ));
        }

        if !matches!(catalog_policy.mode, lpm_workspace::CatalogMode::Manual) {
            if let Some(catalog_range) =
                catalog_policy.optional_catalog_entry("default", &entry.name)
            {
                let resolved = resolved.ok_or_else(|| {
                    LpmError::Registry(format!(
                        "catalogMode: resolver did not report a concrete version for `{}`",
                        entry.name
                    ))
                })?;
                if catalog_range_matches_resolved(&entry.name, catalog_range, resolved)? {
                    if doc[dep_key][&entry.name].as_str() != Some("catalog:") {
                        doc[dep_key][&entry.name] =
                            serde_json::Value::String("catalog:".to_string());
                        doc_mutated = true;
                    }
                    continue;
                }

                let requested_spec = catalog_mode_requested_spec(&entry.intent, resolved);
                match catalog_policy.mode {
                    lpm_workspace::CatalogMode::Strict => {
                        return Err(catalog_mode_mismatch_error(
                            &entry.name,
                            &requested_spec,
                            catalog_range,
                        ));
                    }
                    lpm_workspace::CatalogMode::Prefer => {
                        output::warn(&format!(
                            "Catalog version mismatch for {}: using direct version {} instead of catalog:{}.",
                            entry.name, requested_spec, catalog_range
                        ));
                    }
                    lpm_workspace::CatalogMode::Manual => unreachable!("guarded above"),
                }
            } else if matches!(catalog_policy.mode, lpm_workspace::CatalogMode::Strict) {
                return Err(LpmError::Registry(format!(
                    "catalogMode strict rejected {}: no default catalog entry exists for this package",
                    entry.name
                )));
            }
        }

        if matches!(entry.kind, StagedKind::Placeholder | StagedKind::DistTag) {
            let staged_spec = match (&entry.kind, &entry.intent) {
                (StagedKind::Placeholder, _) => STAGE_PLACEHOLDER.to_string(),
                (StagedKind::DistTag, crate::save_spec::UserSaveIntent::DistTag(tag)) => {
                    tag.clone()
                }
                _ => unreachable!("deferred staged entry must be bare placeholder or dist-tag"),
            };

            let resolved = resolved.ok_or_else(|| {
                LpmError::Registry(format!(
                    "finalize: resolver did not report a concrete version for `{}` \
                     (staged with provisional spec `{staged_spec}`). Refusing to leave the \
                     provisional spec in {}.",
                    entry.name,
                    staged.pkg_json_path.display(),
                ))
            })?;

            let decision = crate::save_spec::decide_saved_dependency_spec(
                &entry.intent,
                resolved,
                flags,
                config,
            );

            doc[dep_key][&entry.name] = serde_json::Value::String(decision.spec_to_write);
            doc_mutated = true;
        }
    }

    if doc_mutated {
        let updated =
            serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
        lpm_common::write_file_atomic(&staged.pkg_json_path, format!("{updated}\n"))?;
    }
    Ok(())
}

pub(super) fn catalog_range_matches_resolved(
    package: &str,
    catalog_range: &str,
    resolved: &lpm_semver::Version,
) -> Result<bool, LpmError> {
    let range = lpm_semver::VersionReq::parse(catalog_range).map_err(|e| {
        LpmError::Registry(format!(
            "catalogMode: invalid default catalog range for `{package}` (`{catalog_range}`): {e}"
        ))
    })?;
    Ok(range.matches(resolved))
}

pub(super) fn catalog_reference(catalog_name: &str) -> String {
    if catalog_name == "default" {
        "catalog:".to_string()
    } else {
        format!("catalog:{catalog_name}")
    }
}

pub(super) fn forced_catalog_flag(catalog_name: &str) -> String {
    if catalog_name == "default" {
        "--catalog".to_string()
    } else {
        format!("--catalog={catalog_name}")
    }
}

pub(super) fn catalog_mode_requested_spec(
    intent: &crate::save_spec::UserSaveIntent,
    resolved: &lpm_semver::Version,
) -> String {
    match intent {
        crate::save_spec::UserSaveIntent::Bare => resolved.to_string(),
        _ => intent_to_range_string(intent),
    }
}

pub(super) fn catalog_mode_mismatch_error(
    package: &str,
    requested_spec: &str,
    catalog_range: &str,
) -> LpmError {
    LpmError::Registry(format!(
        "catalogMode strict rejected {package}@{requested_spec}: default catalog has catalog:{catalog_range}"
    ))
}

pub(super) fn forced_catalog_mismatch_error(
    catalog_name: &str,
    package: &str,
    requested_spec: &str,
    catalog_range: &str,
) -> LpmError {
    LpmError::Registry(format!(
        "{} rejected {package}@{requested_spec}: catalog `{catalog_name}` has catalog:{catalog_range}",
        forced_catalog_flag(catalog_name)
    ))
}

pub(super) fn resolve_catalog_policy_manifest_spec(
    package: &str,
    specifier: &str,
    catalog_policy: &CatalogSavePolicy,
) -> Result<String, LpmError> {
    if !specifier.starts_with("catalog:") {
        return Ok(specifier.to_string());
    }

    let mut deps = HashMap::from([(package.to_string(), specifier.to_string())]);
    lpm_workspace::resolve_catalog_protocol(&mut deps, &catalog_policy.catalogs)
        .map_err(catalog_protocol_error_to_lpm)?;
    deps.remove(package).ok_or_else(|| {
        LpmError::Registry(format!(
            "catalogMode: failed to resolve catalog protocol for `{package}`"
        ))
    })
}

pub(super) async fn resolve_catalog_policy_candidate_version(
    client: &RegistryClient,
    route_table: &RouteTable,
    package: &str,
    requested_spec: &str,
) -> Result<lpm_semver::Version, LpmError> {
    let resolved = if lpm_common::package_name::is_lpm_package(package) {
        let pkg_name = lpm_common::PackageName::parse(package)
            .map_err(|e| LpmError::Registry(e.to_string()))?;
        client.get_package_metadata(&pkg_name).await?
    } else {
        let route = route_table.route_for_package(package);
        client.get_npm_metadata_routed(package, route).await?
    }
    .resolve_version_spec(requested_spec)?;

    lpm_semver::Version::parse(&resolved).map_err(|e| {
        LpmError::Registry(format!(
            "catalogMode: resolved version `{resolved}` for `{package}` did not parse as semver: {e}"
        ))
    })
}

pub(super) async fn preflight_catalog_policy_rejection(
    client: &RegistryClient,
    route_cwd: &Path,
    staged: &StagedManifest,
    catalog_policy: &CatalogSavePolicy,
) -> Result<(), LpmError> {
    let forced_catalog = catalog_policy.forced_catalog.as_deref();
    let strict_mode = matches!(catalog_policy.mode, lpm_workspace::CatalogMode::Strict);
    if forced_catalog.is_none() && !strict_mode {
        return Ok(());
    }

    let content = std::fs::read_to_string(&staged.pkg_json_path)?;
    let doc: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;
    let dep_key = if staged.save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };
    let route_table = RouteTable::from_env_and_filesystem(route_cwd)
        .map_err(|e| LpmError::Registry(format!("npmrc: {e}")))?;

    for entry in &staged.entries {
        let manifest_spec = doc
            .get(dep_key)
            .and_then(|deps| deps.get(&entry.name))
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "catalogMode: staged manifest is missing `{}` under {}",
                    entry.name, dep_key
                ))
            })?;

        let effective_spec =
            resolve_catalog_policy_manifest_spec(&entry.name, manifest_spec, catalog_policy)?;

        if let Some(catalog_name) = forced_catalog {
            let catalog_range = catalog_policy.catalog_entry(catalog_name, &entry.name)?;
            let resolved = resolve_catalog_policy_candidate_version(
                client,
                &route_table,
                &entry.name,
                &effective_spec,
            )
            .await?;
            if !catalog_range_matches_resolved(&entry.name, catalog_range, &resolved)? {
                let requested_spec = catalog_mode_requested_spec(&entry.intent, &resolved);
                return Err(forced_catalog_mismatch_error(
                    catalog_name,
                    &entry.name,
                    &requested_spec,
                    catalog_range,
                ));
            }
            continue;
        }

        let Some(catalog_range) = catalog_policy.optional_catalog_entry("default", &entry.name)
        else {
            return Err(LpmError::Registry(format!(
                "catalogMode strict rejected {}: no default catalog entry exists for this package",
                entry.name
            )));
        };

        let resolved = resolve_catalog_policy_candidate_version(
            client,
            &route_table,
            &entry.name,
            &effective_spec,
        )
        .await?;
        if !catalog_range_matches_resolved(&entry.name, catalog_range, &resolved)? {
            let requested_spec = catalog_mode_requested_spec(&entry.intent, &resolved);
            return Err(catalog_mode_mismatch_error(
                &entry.name,
                &requested_spec,
                catalog_range,
            ));
        }
    }

    Ok(())
}

/// Rewrite staged dist-tag literals to exact versions before the resolver runs.
///
/// The CLI `install pkg@beta` flow needs two different representations of the
/// same user input:
///
/// - the original dist-tag intent for finalize, so `package.json` can later be
///   saved as `^resolved` or exact-prerelease per save-policy rules
/// - an exact version in the staged manifest so the resolver never has to parse
///   a raw dist-tag like `beta`
///
/// `stage_packages_to_manifest` preserves the dist-tag literal and stores the
/// original [`UserSaveIntent::DistTag`] on each [`StagedEntry`]. This helper is
/// the second step: resolve those staged tags through the same routed metadata
/// path install already uses (`.npmrc` custom registries included), then patch
/// just the staged manifest entries to their concrete versions.
pub(super) async fn pin_staged_dist_tags_for_resolution(
    client: &RegistryClient,
    route_cwd: &Path,
    staged: &StagedManifest,
) -> Result<(), LpmError> {
    let dist_tag_entries: Vec<(&str, &str)> = staged
        .entries
        .iter()
        .filter_map(|entry| match &entry.intent {
            crate::save_spec::UserSaveIntent::DistTag(tag) => {
                Some((entry.name.as_str(), tag.as_str()))
            }
            _ => None,
        })
        .collect();

    if dist_tag_entries.is_empty() {
        return Ok(());
    }

    let route_table = lpm_registry::RouteTable::from_env_and_filesystem(route_cwd)
        .map_err(|e| LpmError::Registry(format!("npmrc: {e}")))?;

    let content = std::fs::read_to_string(&staged.pkg_json_path)?;
    let mut doc: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| LpmError::Registry(e.to_string()))?;

    let dep_key = if staged.save_dev {
        "devDependencies"
    } else {
        "dependencies"
    };

    for (name, tag) in dist_tag_entries {
        let resolved_version = if lpm_common::package_name::is_lpm_package(name) {
            let pkg_name = lpm_common::PackageName::parse(name)
                .map_err(|e| LpmError::Registry(e.to_string()))?;
            client.get_package_metadata(&pkg_name).await?
        } else {
            let route = route_table.route_for_package(name);
            client.get_npm_metadata_routed(name, route).await?
        }
        .resolve_version_spec(tag)?;

        doc[dep_key][name] = serde_json::Value::String(resolved_version);
    }

    let updated =
        serde_json::to_string_pretty(&doc).map_err(|e| LpmError::Registry(e.to_string()))?;
    lpm_common::write_file_atomic(&staged.pkg_json_path, format!("{updated}\n"))?;
    Ok(())
}

/// Install specific packages: add them to package.json then run full install.
/// For Swift packages (ecosystem=swift), uses SE-0292 registry mode instead.
///
/// Handles specs like: `express`, `express@^4.0.0`, `@lpm.dev/neo.highlight@1.0.0`
///
/// this is the legacy path used when no `--filter`
/// or `-w` flag is set AND we're not inside a workspace member directory.
/// New filtered paths go through `run_install_filtered_add` instead, which
/// handles workspace-aware target resolution but rejects Swift packages
/// (SE-0292 workspace support is deferred toa future release).
///
/// `save_flags` carries the per-command save-spec overrides
/// (`--exact`, `--tilde`, `--save-prefix`). They flow through stage and
/// finalize so the manifest write reflects the user's explicit policy.
#[allow(clippy::too_many_arguments)]
pub async fn run_add_packages(
    client: &RegistryClient,
    project_dir: &Path,
    packages: &[String],
    save_dev: bool,
    json_output: bool,
    yes: bool,
    allow_new: bool,
    force: bool,
    save_flags: crate::save_spec::SaveFlags,
    catalog_name_override: Option<&str>,
    // forwarded CLI-side policy override. See
    // [`run_with_options`] for the resolution precedence and the
    // current consumer (triage-mode install summary line).
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    // forwarded `--advisor` override. Opaque
    // pass-through to `run_with_options` — see that fn for the
    // precedence chain and validation contract.
    advisor_override: Option<String>,
    //: forwarded `--min-release-age=<dur>` override.
    // Opaque pass-through — see [`run_with_options`].
    min_release_age_override: Option<u64>,
    min_release_age_exclude: &[String],
    // forwarded `--ignore-provenance-drift[-all]`
    // policy. Opaque pass-through — see [`run_with_options`].
    drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    // forwarded composed Sigstore verifier policy. Opaque
    // pass-through — see [`run_with_options`].
    verify_policy: crate::provenance_fetch::VerifyPolicy,
    // forwarded strict peer-dependency override — see [`run_with_options`].
    strict_peer_dependencies_override: Option<bool>,
    omit_policy: InstallOmitPolicy,
    // forwarded CLI sandbox-mode
    // overrides. Opaque pass-through — see [`run_with_options`].
    strict_sandbox: bool,
    no_sandbox: bool,
    // forwarded top-level `--verbose` flag — see [`run_with_options`].
    verbose: bool,
    // forwarded resolved audit-after-install boolean — see [`run_with_options`].
    audit_after_install: bool,
    timing: bool,
) -> Result<(), LpmError> {
    let reviewed = crate::typosquat_guard::guard_explicit_package_specs(
        project_dir,
        packages,
        &[project_dir.to_path_buf()],
        yes,
        json_output,
    )?;
    let packages = reviewed.specs;

    // First pass: check if any LPM packages are Swift ecosystem
    // Route Swift packages to SE-0292 registry mode
    let mut js_packages = Vec::new();

    for spec in &packages {
        let (name, intent) = crate::save_spec::parse_user_save_intent(spec)?;
        let range = intent_to_range_string(&intent);

        if name.starts_with("@lpm.dev/") {
            // Fetch metadata to check ecosystem
            let pkg_name = lpm_common::PackageName::parse(&name)?;
            let metadata = client.get_package_metadata(&pkg_name).await?;
            let latest_ver = metadata
                .latest_version_tag()
                .ok_or_else(|| LpmError::NotFound(format!("no versions for {name}")))?;

            // Resolve the user-specified version range against available versions.
            // Falls back to latest when no version is specified.
            let resolved_ver = resolve_version_from_spec(&range, &metadata, latest_ver)?;
            let ver_meta = metadata.version(resolved_ver).ok_or_else(|| {
                LpmError::NotFound(format!("version {resolved_ver} not found for {name}"))
            })?;

            if ver_meta.effective_ecosystem() == "swift" {
                // SE-0292 registry mode
                run_swift_install(
                    project_dir,
                    &pkg_name,
                    resolved_ver,
                    ver_meta,
                    json_output,
                    client.base_url(),
                )
                .await?;
                continue;
            }
        }

        js_packages.push(spec.clone());
    }

    // If all packages were Swift, we're done
    if js_packages.is_empty() {
        return Ok(());
    }

    // ── stage → install → finalize, wrapped in a transaction
    // that covers the FULL install state surface. Invariant:
    // snapshot the manifest AND the lockfile so a failed install rolls
    // both back together, and invalidate `.lpm/install-hash` so the next
    // install re-resolves and reconciles `node_modules/` (which we don't
    // snapshot — too large). ──────────────────────────────────────────
    let pkg_json_path = project_dir.join("package.json");
    let lockfile_path = project_dir.join(lpm_lockfile::LOCKFILE_NAME);
    let lockfile_bin_path = lockfile_path.with_extension("lockb");
    let install_hash_path = project_dir.join(".lpm").join("install-hash");
    let pnpm_workspace_path = project_dir.join("pnpm-workspace.yaml");

    // ** fix.** Wrap the entire snapshot → stage → install
    // → finalize → commit window in a per-project exclusive lock so
    // concurrent `lpm install <pkg>` invocations on the same project
    // serialize. Previously, both processes would snapshot the same
    // pre-edit `package.json`, both stage their own dep on top, and
    // the second-to-commit silently overwrote the first's edits
    // (data-loss-grade). The lock is per-project (no cross-project
    // contention) and held across all `?` early-exits via the async
    // block's return.
    //
    // `run_with_options` (called below) does NOT acquire this lock
    // itself — wrapping it would deadlock when called from inside
    // this block. The lock surface is the OUTER transaction; the
    // inner install pipeline runs under the assumption that the
    // caller has serialized the snapshot+commit window.
    let project_lock = lpm_common::project_install_lock(project_dir);
    lpm_common::with_exclusive_lock_async(project_lock, async {
        // 1. Snapshot the install state surface. Manifest is required (must
        // exist by precondition); lockfile + binary lockfile are optional
        // (absent on a fresh project); install-hash is invalidate-only
        // (cache file, deleted on rollback regardless of pre-state).
        let optional_refs = [
            lockfile_path.as_path(),
            lockfile_bin_path.as_path(),
            pnpm_workspace_path.as_path(),
        ];
        let tx = crate::manifest_tx::ManifestTransaction::snapshot_install_state(
            &[&pkg_json_path],
            &optional_refs,
            &[&install_hash_path],
        )?;
        maybe_test_panic("after-snapshot");

        // 2. Stage the new entries. Explicit specs land verbatim; bare/dist-tag
        // entries get a `*` placeholder that finalize will replace using the
        // save policy (resolved version + flags + config).
        //
        // Step 6: load `./lpm.toml` (project) merged with
        // `~/.lpm/config.toml` (global) for the persistent save-policy
        // keys. CLI flags still beat config inside `decide_saved_dependency_spec`.
        let save_config = crate::save_config::SaveConfigLoader::load_for_project(project_dir)?;
        let catalog_policy = catalog_save_policy_for_project(project_dir, catalog_name_override)?;
        let staged =
            stage_packages_to_manifest(&pkg_json_path, &js_packages, save_dev, save_flags)?;
        pin_staged_dist_tags_for_resolution(client, project_dir, &staged).await?;
        preflight_catalog_policy_rejection(client, project_dir, &staged, &catalog_policy).await?;
        maybe_test_panic("after-stage");

        // 3. Run the full install pipeline, capturing the direct-dep version
        // map via the out-param. If anything fails, the `?`
        // returns early — `tx` drops without `commit()` and the manifest
        // snaps back to its pre-stage state. The placeholder never survives.
        // We intentionally keep any existing lockfile on disk so the
        // pipeline can diff against the pre-install direct graph. The warm
        // fast-path validator below now rejects stale lockfiles whose kept
        // entries no longer satisfy the staged manifest, so keeping the file
        // does not suppress a needed re-resolve.
        let mut direct_versions: HashMap<String, lpm_semver::Version> = HashMap::new();
        run_with_options(
            client,
            project_dir,
            json_output,
            false, // offline
            FrozenLockfileMode::Never,
            force,
            allow_new,
            false, // strict_integrity — internal call, no flag
            strict_peer_dependencies_override,
            None,  // linker_override
            false, // no_skills
            false, // no_editor_setup
            false, // no_security_summary
            false, // auto_build
            None,  // target_set: legacy single-project path
            Some(&mut direct_versions),
            Some(js_packages.len()),
            script_policy_override,
            advisor_override,
            min_release_age_override,
            min_release_age_exclude,
            drift_ignore_policy,
            verify_policy,
            omit_policy,
            strict_sandbox,
            no_sandbox,
            verbose,
            audit_after_install,
            timing,
            &[],
        )
        .await?;
        maybe_test_panic("after-install");

        // 5. Finalize the manifest using the resolved direct-dep versions
        // from the resolver. No-op if stage produced no placeholders.
        finalize_packages_in_manifest_with_catalog_policy(
            &staged,
            &direct_versions,
            save_flags,
            save_config,
            &catalog_policy,
        )?;
        maybe_test_panic("after-finalize");

        cleanup_unused_catalogs_after_install(project_dir)?;

        // 6. All steps succeeded — commit the transaction so the manifest
        // edits persist.
        tx.commit();
        Ok(())
    })
    .await
}

/// workspace-aware install entry point.
///
/// Resolves CLI `--filter` / `-w` / cwd into a concrete set of
/// `package.json` files via [`crate::commands::install_targets`], mutates
/// each one with the requested package specs, then runs the install
/// pipeline ONCE at the resolved `install_root`.
///
/// **Swift packages**: this path treats every package as JS — Swift
/// `ecosystem=swift` packages added through this path will be written into
/// the target `package.json` files but the SE-0292 routing in
/// `run_swift_install` will not fire. Workspace-aware Swift install is
/// tracked undera future release. For pure Swift workflows, use the legacy
/// path: `cd <project> && lpm install @scope/swift-pkg` (no `-w` / `--filter`).
///
/// `save_flags` carries the per-command save-spec overrides
/// applied to every targeted member's manifest finalize step.
#[allow(clippy::too_many_arguments)]
pub async fn run_install_filtered_add(
    client: &RegistryClient,
    cwd: &Path,
    packages: &[String],
    save_dev: bool,
    filters: &[String],
    filter_prod: &[String],
    changed_files_ignore_pattern: &[String],
    test_pattern: &[String],
    workspace_root_flag: bool,
    fail_if_no_match: bool,
    yes: bool,
    json_output: bool,
    allow_new: bool,
    force: bool,
    save_flags: crate::save_spec::SaveFlags,
    catalog_name_override: Option<&str>,
    // forwarded CLI-side policy override.
    script_policy_override: Option<crate::script_policy_config::ScriptPolicy>,
    // forwarded `--advisor` override. Opaque
    // pass-through to `run_with_options` — see that fn for the
    // precedence chain and validation contract.
    advisor_override: Option<String>,
    //: forwarded `--min-release-age=<dur>` override.
    // Opaque pass-through — see [`run_with_options`].
    min_release_age_override: Option<u64>,
    min_release_age_exclude: &[String],
    // forwarded `--ignore-provenance-drift[-all]`
    // policy. Opaque pass-through — see [`run_with_options`].
    drift_ignore_policy: crate::provenance_fetch::DriftIgnorePolicy,
    // forwarded composed Sigstore verifier policy. Opaque
    // pass-through — see [`run_with_options`].
    verify_policy: crate::provenance_fetch::VerifyPolicy,
    // forwarded strict peer-dependency override — see [`run_with_options`].
    strict_peer_dependencies_override: Option<bool>,
    omit_policy: InstallOmitPolicy,
    // forwarded CLI sandbox-mode
    // overrides. Opaque pass-through — see [`run_with_options`].
    strict_sandbox: bool,
    no_sandbox: bool,
    // forwarded top-level `--verbose` — see [`run_with_options`].
    verbose: bool,
    // forwarded resolved audit-after-install boolean — see [`run_with_options`].
    audit_after_install: bool,
    timing: bool,
) -> Result<(), LpmError> {
    // 1. Resolve CLI flags into a concrete target list.
    let targets = crate::commands::install_targets::resolve_install_targets(
        cwd,
        filters,
        filter_prod,
        changed_files_ignore_pattern,
        test_pattern,
        workspace_root_flag,
        true, // has_packages — install_filtered_add is only called with non-empty packages
    )?;

    // 2. Empty result handling (--fail-if-no-match mirrors ).
    //
    // When the filter set returns empty and any filter looks like a bare
    // name that would have matched under the old substring behavior, surface
    // the same substring-to-glob migration hint as `lpm run --filter` and
    // `lpm filter`. Otherwise those users get a generic "no packages matched"
    // with no recovery path.
    if targets.member_manifests.is_empty() {
        let hint = crate::commands::filter::format_no_match_hint_for_sets(filters, filter_prod);

        if fail_if_no_match {
            let base = "no workspace packages matched the filter (--fail-if-no-match)";
            return Err(LpmError::Script(match hint {
                Some(h) => format!("{base}\n\n{h}"),
                None => base.to_string(),
            }));
        }
        if !json_output {
            output::warn("No packages matched the filter; nothing to install.");
            if let Some(h) = hint {
                eprintln!();
                for line in h.lines() {
                    eprintln!("  {}", line.dimmed());
                }
                eprintln!();
            }
        }
        return Ok(());
    }

    let member_install_roots: Vec<PathBuf> = targets
        .member_manifests
        .iter()
        .map(|m| crate::commands::install_targets::install_root_for(m).to_path_buf())
        .collect();
    let workspace_root_for_config: PathBuf = lpm_workspace::discover_workspace(cwd)
        .ok()
        .flatten()
        .map_or_else(|| cwd.to_path_buf(), |ws| ws.root);
    let reviewed = crate::typosquat_guard::guard_explicit_package_specs(
        &workspace_root_for_config,
        packages,
        &member_install_roots,
        yes,
        json_output,
    )?;
    let packages = reviewed.specs;

    // 3. Multi-member confirmation prompt.
    //
    // ** ** — the original plan included an
    // interactive y/N prompt gated on `multi_member && is_tty && !json_output`
    // and a `confirm_multi_member_mutation` helper. The implementation
    // initially shipped preview-only (no prompt); that gap is closed here.
    //
    // Contract:
    // - JSON mode: print the target set in the existing JSON payload, no
    // prompt (agents get a single parseable result).
    // - Non-TTY stdin (CI, subprocess, redirected input): print preview, no
    // prompt, proceed (legacy behavior preserved for scripts).
    // - `--yes` / `-y`: print preview, no prompt, proceed (scripts + agents
    // that WANT the TTY branch but don't want to answer).
    // - Interactive TTY + not `--yes` + not JSON: print preview, ask
    // "Proceed? [y/N]", default is No. User decline returns an error that
    // halts BEFORE any `package.json` is touched.
    if targets.multi_member {
        confirm_multi_member_mutation(
            "Adding",
            packages.len(),
            &targets.member_manifests,
            yes,
            json_output,
        )?;
    }

    // 4. Iterate per target. For EACH targeted manifest:
    // a. Mutate the manifest with the new package entries.
    // b. Remove that member's lockfile to force re-resolution.
    // c. Run the install pipeline AT THE MEMBER'S DIR (not at the
    // workspace root). LPM uses per-directory lockfiles + node_modules,
    // so this is the only place the new dependency will be installed
    // and linked correctly.
    //
    // A single install pipeline at the workspace root would silently drop
    // member-targeted installs on workspaces with no root deps.
    //
    // For multi-target filtered installs (`--filter "ui-*"` matching N
    // members), the pipeline runs N times sequentially. JSON output mode
    // produces N JSON objects on stdout (JSON-Lines), one per member.
    let target_paths: Vec<String> = targets
        .member_manifests
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    // ── snapshot the FULL install state surface for every
    // targeted member in a single transaction. Invariant:
    // each member contributes its own (manifest, lockfile, lockfile.b,
    // install-hash) quadruple. A failure halfway through a multi-member
    // install rolls every touched member back; earlier members'
    // node_modules trees are left as-is, but their install-hash files
    // are invalidated so the next `lpm install` re-resolves and
    // converges. ──────────────────────────────────────────────────────

    // Compute per-member install roots and the four state paths.
    let lockfile_paths: Vec<PathBuf> = member_install_roots
        .iter()
        .map(|r| r.join(lpm_lockfile::LOCKFILE_NAME))
        .collect();
    let lockfile_bin_paths: Vec<PathBuf> = lockfile_paths
        .iter()
        .map(|p| p.with_extension("lockb"))
        .collect();
    let install_hash_paths: Vec<PathBuf> = member_install_roots
        .iter()
        .map(|r| r.join(".lpm").join("install-hash"))
        .collect();

    // Workspace-aware config resolution reads from the workspace root, and
    // catalog cleanup can mutate the root package even when only a member was
    // targeted.
    let root_package_json_path = workspace_root_for_config.join("package.json");
    let pnpm_workspace_path = workspace_root_for_config.join("pnpm-workspace.yaml");

    // Build the (required, optional, invalidate) reference slices the
    // transaction expects. `required` = manifests; `optional` = lockfile
    // + lockfile.b for every member; `invalidate` = install-hash for
    // every member.
    let mut required_paths = targets.member_manifests.clone();
    if !required_paths
        .iter()
        .any(|path| path == &root_package_json_path)
    {
        required_paths.push(root_package_json_path);
    }
    let required_refs: Vec<&Path> = required_paths.iter().map(|p| p.as_path()).collect();
    let mut optional_refs: Vec<&Path> = Vec::with_capacity(lockfile_paths.len() * 2 + 1);
    for p in &lockfile_paths {
        optional_refs.push(p.as_path());
    }
    for p in &lockfile_bin_paths {
        optional_refs.push(p.as_path());
    }
    optional_refs.push(pnpm_workspace_path.as_path());
    let invalidate_refs: Vec<&Path> = install_hash_paths.iter().map(|p| p.as_path()).collect();

    // per-command save flags from the CLI flow into stage and
    // finalize so multi-member installs honor `--exact`/`--tilde`/etc.
    // for every targeted member identically.
    //
    // **Workspace-aware config resolution (Invariant:):** the
    // project-tier `lpm.toml` MUST be read from the WORKSPACE ROOT, not
    // from `cwd`. Save policy is a workspace-wide preference; per-member
    // overrides would create incoherent multi-member installs where the
    // same `--filter "ui-*"` produces different prefixes per member.
    //
    // Previously this read from `cwd` directly, which broke the moment a
    // user invoked `lpm install ms --filter app` from
    // `packages/app/` instead of from the workspace root: `cwd` was the
    // member dir, no `lpm.toml` lived there, and the loader silently
    // returned defaults. Now we walk up via `discover_workspace` and
    // pass the discovered root to the loader. Falls back to `cwd` only
    // when no workspace is discoverable (defensive — this path is only
    // reachable from a workspace context, but the fallback keeps the
    // loader call infallible if `discover_workspace` ever returns None
    // through some future code change).
    let save_config =
        crate::save_config::SaveConfigLoader::load_for_project(&workspace_root_for_config)?;
    let catalog_policy =
        catalog_save_policy_for_project(&workspace_root_for_config, catalog_name_override)?;

    // ** fix.** Wrap the workspace-install snapshot → loop
    // → commit in an exclusive per-WORKSPACE lock. Two concurrent
    // `lpm install --filter <member>` invocations on the same workspace
    // serialize through this lock so the multi-member ManifestTransaction
    // doesn't race with itself. Per-member locks would be more granular
    // but require sorted-acquisition to avoid deadlock between two
    // processes targeting overlapping member sets — the workspace-root
    // lock is the simpler correct primitive for v1. Sibling lock to the
    // single-project path's per-project lock; same `.install.lock`
    // filename so a future refactor can unify them.
    let workspace_lock = lpm_common::project_install_lock(&workspace_root_for_config);
    lpm_common::with_exclusive_lock_async(workspace_lock, async {
        let tx = crate::manifest_tx::ManifestTransaction::snapshot_install_state(
            &required_refs,
            &optional_refs,
            &invalidate_refs,
        )?;

        let mut staged_manifests: Vec<StagedManifest> =
            Vec::with_capacity(targets.member_manifests.len());
        let mut last_err: Option<LpmError> = None;
        for (idx, manifest_path) in targets.member_manifests.iter().enumerate() {
            // (a) Stage the target manifest. Explicit specs land verbatim;
            // bare/dist-tag entries get a `*` placeholder.
            let staged =
                match stage_packages_to_manifest(manifest_path, &packages, save_dev, save_flags) {
                    Ok(s) => s,
                    Err(e) => {
                        last_err = Some(e);
                        break;
                    }
                };

            // Use the precomputed install root so the transaction
            // snapshot above and the loop below agree on the exact
            // member path (no double-compute, no path drift).
            let install_root = &member_install_roots[idx];

            if let Err(e) = pin_staged_dist_tags_for_resolution(client, install_root, &staged).await
            {
                last_err = Some(e);
                break;
            }

            if let Err(e) =
                preflight_catalog_policy_rejection(client, install_root, &staged, &catalog_policy)
                    .await
            {
                last_err = Some(e);
                break;
            }

            staged_manifests.push(staged);
        }

        if let Some(e) = last_err {
            return Err(e);
        }

        for (idx, staged) in staged_manifests.iter().enumerate() {
            let install_root = &member_install_roots[idx];

            // (b) Run the install pipeline at THIS member's directory,
            // capturing the direct-dep map for finalize via the // out-param.
            // We intentionally keep each member's existing lockfile so the
            // install pipeline can diff against the pre-install direct
            // graph. The warm fast-path validator rejects stale lockfiles
            // that no longer satisfy the staged manifest.
            let mut direct_versions: HashMap<String, lpm_semver::Version> = HashMap::new();
            let result = run_with_options(
                client,
                install_root,
                json_output,
                false, // offline
                FrozenLockfileMode::Never,
                force,
                allow_new,
                false, // strict_integrity — workspace-add path, no flag
                strict_peer_dependencies_override,
                None,  // linker_override
                false, // no_skills
                false, // no_editor_setup
                false, // no_security_summary
                false, // auto_build
                Some(&target_paths),
                Some(&mut direct_versions),
                Some(packages.len()),
                script_policy_override,
                // Same per-iteration clone rationale as `drift_ignore_policy`
                // below: each loop pass moves the override into
                // `run_with_options`, so the multi-member loop has to clone.
                // `Option<String>` is cheap to clone.
                advisor_override.clone(),
                min_release_age_override,
                min_release_age_exclude,
                // Multi-member loop: `run_install_filtered_add` runs the
                // install pipeline once per targeted member. Each
                // iteration consumes the policy, so we clone per call.
                // Cloning an enum + HashSet of ignored names is cheap
                // relative to the per-iteration install pipeline itself.
                drift_ignore_policy.clone(),
                // Same per-iteration clone rationale as drift_ignore_policy.
                // `VerifyPolicy` carries an `EnforceMode` (Copy) and a
                // `SkipPolicy` (HashSet of skip-listed names); cloning is
                // bounded by the user-passed flag count.
                verify_policy.clone(),
                omit_policy,
                strict_sandbox,
                no_sandbox,
                verbose,
                audit_after_install,
                timing,
                &[],
            )
            .await;

            if let Err(e) = result {
                // Abort on first failure. Half-installed multi-member states
                // are confusing and the user should fix the failure before
                // retrying. The transaction guard restores ALL touched
                // manifests when we drop without commit.
                last_err = Some(e);
                break;
            }

            // (d) Finalize this member's manifest using the direct-dep
            // versions from the resolver.
            if let Err(e) = finalize_packages_in_manifest_with_catalog_policy(
                staged,
                &direct_versions,
                save_flags,
                save_config,
                &catalog_policy,
            ) {
                last_err = Some(e);
                break;
            }
        }

        if let Some(e) = last_err {
            // Drop `tx` here without committing → every snapshotted manifest
            // is restored to its pre-stage bytes.
            return Err(e);
        }

        cleanup_unused_catalogs_after_install(&workspace_root_for_config)?;

        // All members succeeded — persist every staged + finalized manifest.
        tx.commit();
        Ok(())
    })
    .await
}
