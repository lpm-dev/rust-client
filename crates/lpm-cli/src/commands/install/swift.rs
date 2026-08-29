use super::*;

#[derive(Clone, Copy)]
pub(super) struct SwiftInstallOptions<'a> {
    pub(super) yes: bool,
    pub(super) json_output: bool,
    pub(super) audit_after_install: bool,
    pub(super) registry_url: &'a str,
    pub(super) session: Option<&'a lpm_auth::SessionManager>,
}

pub(super) struct SwiftInstallRequest<'a> {
    pub(super) name: &'a lpm_common::PackageName,
    pub(super) version: &'a str,
    pub(super) ver_meta: &'a lpm_registry::VersionMetadata,
    pub(super) requirement: crate::swift_manifest::SwiftRequirement,
}

struct PreparedSwiftInstall<'a> {
    request: &'a SwiftInstallRequest<'a>,
    se0292_id: String,
    product: &'a lpm_registry::SwiftProduct,
}

fn prepare_swift_installs<'a>(
    requests: &'a [SwiftInstallRequest<'a>],
) -> Result<Vec<PreparedSwiftInstall<'a>>, LpmError> {
    requests
        .iter()
        .map(|request| {
            let product = request.ver_meta.swift_library_product().ok_or_else(|| {
                LpmError::Registry(format!(
                    "{}@{} does not publish a Swift library product",
                    request.name.scoped(),
                    request.version
                ))
            })?;
            if product.targets.is_empty() {
                return Err(LpmError::Registry(format!(
                    "Swift library product '{}' for {}@{} does not declare an importable module",
                    product.name,
                    request.name.scoped(),
                    request.version
                )));
            }
            Ok(PreparedSwiftInstall {
                request,
                se0292_id: crate::swift_manifest::lpm_to_se0292_id(request.name),
                product,
            })
        })
        .collect()
}

pub(super) async fn run_swift_install_batch(
    project_dir: &Path,
    requests: &[SwiftInstallRequest<'_>],
    options: SwiftInstallOptions<'_>,
) -> Result<serde_json::Value, LpmError> {
    if requests.is_empty() {
        return Ok(serde_json::json!({"packages": []}));
    }
    let manifest_path = crate::swift_manifest::find_package_swift(project_dir);
    let xcodeproj_path = crate::xcode_project::find_xcodeproj(project_dir)?;
    match (manifest_path, xcodeproj_path) {
        (Some(manifest), _) => {
            run_swift_install_spm_batch(project_dir, &manifest, requests, options).await
        }
        (None, Some(xcodeproj)) => {
            run_swift_install_xcode_batch(project_dir, &xcodeproj, requests, options).await
        }
        (None, None) => Err(LpmError::Registry(
            "No Package.swift or .xcodeproj found. Initialize a Swift project first.".into(),
        )),
    }
}

pub(super) async fn run_swift_install_spm_batch(
    project_dir: &Path,
    manifest_path: &Path,
    requests: &[SwiftInstallRequest<'_>],
    options: SwiftInstallOptions<'_>,
) -> Result<serde_json::Value, LpmError> {
    let prepared = prepare_swift_installs(requests)?;
    let manifest_dir = manifest_path.parent().unwrap_or(project_dir);
    let targets = crate::swift_manifest::get_spm_targets(manifest_dir)?;
    let target_name = select_spm_target(&targets, options.yes)?;
    let dependencies = prepared
        .iter()
        .map(|package| crate::swift_manifest::RegistryDependency {
            se0292_id: &package.se0292_id,
            requirement: package.request.requirement.clone(),
            product_name: &package.product.name,
            module_names: &package.product.targets,
        })
        .collect::<Vec<_>>();
    let edits = crate::swift_manifest::reconcile_registry_dependencies(
        manifest_path,
        &target_name,
        &dependencies,
    )?;
    finish_swift_batch(manifest_dir, &prepared, &edits, &target_name, None, options).await
}

fn select_spm_target(targets: &[String], yes: bool) -> Result<String, LpmError> {
    match targets {
        [] => Err(LpmError::Registry(
            "No non-test targets found in Package.swift (binary and system targets cannot consume package products).".into(),
        )),
        [target] => Ok(target.clone()),
        [first, ..] if yes => Ok(first.clone()),
        _ => {
            let mut selection = cliclack::select("Which target should use this dependency?");
            for (index, target) in targets.iter().enumerate() {
                selection = selection.item(
                    target.clone(),
                    lpm_common::sanitize_terminal_inline(target).into_owned(),
                    "",
                );
                if index == 0 {
                    selection = selection.initial_value(target.clone());
                }
            }
            selection
                .interact()
                .map_err(|error| LpmError::Registry(format!("prompt failed: {error}")))
        }
    }
}

pub(super) async fn run_swift_install_xcode_batch(
    project_dir: &Path,
    xcodeproj_path: &Path,
    requests: &[SwiftInstallRequest<'_>],
    options: SwiftInstallOptions<'_>,
) -> Result<serde_json::Value, LpmError> {
    let prepared = prepare_swift_installs(requests)?;
    let project_root = xcodeproj_path.parent().unwrap_or(project_dir);
    let wrapper = crate::swift_manifest::ensure_wrapper_package(project_root)?;
    let dependencies = prepared
        .iter()
        .map(|package| crate::swift_manifest::RegistryDependency {
            se0292_id: &package.se0292_id,
            requirement: package.request.requirement.clone(),
            product_name: &package.product.name,
            module_names: &package.product.targets,
        })
        .collect::<Vec<_>>();
    let edits = crate::swift_manifest::reconcile_wrapper_dependencies(
        &wrapper.manifest_path,
        &dependencies,
    )?;
    let link_result = crate::xcode_project::link_local_package(
        xcodeproj_path,
        crate::swift_manifest::LPM_DEPS_PACKAGE_NAME,
        crate::swift_manifest::LPM_DEPS_REL_PATH,
    )?;
    let wrapper_dir = wrapper.manifest_path.parent().unwrap_or(project_root);
    let report = finish_swift_batch(
        wrapper_dir,
        &prepared,
        &edits,
        &link_result.target_name,
        Some(&link_result),
        options,
    )
    .await?;
    if link_result.package_ref_added && !options.json_output {
        output::warn("If Xcode is open, close and reopen the project to pick up changes.");
    }
    Ok(report)
}

async fn finish_swift_batch(
    resolve_dir: &Path,
    packages: &[PreparedSwiftInstall<'_>],
    edits: &[crate::swift_manifest::ManifestEdit],
    target_name: &str,
    xcode_link: Option<&crate::xcode_project::XcodeLinkResult>,
    options: SwiftInstallOptions<'_>,
) -> Result<serde_json::Value, LpmError> {
    let changed = edits.iter().any(|edit| !edit.already_exists)
        || xcode_link.is_some_and(|link| link.package_ref_added);
    let registry_setup = if changed {
        let setup = crate::commands::swift_registry::ensure_configured(
            options.session,
            options.registry_url,
            resolve_dir,
            options.json_output,
        )
        .await?;
        if !options.json_output {
            output::info("Resolving Swift packages...");
        }
        crate::swift_manifest::run_swift_resolve(resolve_dir)?;
        Some(setup)
    } else {
        None
    };

    let package_reports = packages
        .iter()
        .zip(edits)
        .map(|(package, edit)| {
            let audit_summary = options.audit_after_install.then(|| {
                crate::commands::audit::summarize_registry_install(
                    &package.request.name.scoped(),
                    package.request.version,
                    package.request.ver_meta,
                )
            });
            let mut report = serde_json::json!({
                "package": package.request.name.scoped(),
                "version": package.request.version,
                "mode": "registry",
                "se0292_id": package.se0292_id,
                "product_name": package.product.name,
                "modules": package.product.targets,
                "target": target_name,
                "already_existed": edit.already_exists,
            });
            if let Some(summary) = audit_summary {
                report["audit_summary"] =
                    serde_json::to_value(summary).unwrap_or(serde_json::Value::Null);
            }
            report
        })
        .collect::<Vec<_>>();

    if !options.json_output {
        for (package, edit) in packages.iter().zip(edits) {
            if edit.already_exists {
                output::info_line(crate::install_ui::terminal_line!(
                    "{} is already installed",
                    install_ui::dim(&package.se0292_id)
                ));
                continue;
            }
            output::success_line(crate::install_ui::terminal_line!(
                "Installed {}@{} via SE-0292 registry",
                install_ui::bold(&package.request.name.scoped()),
                package.request.version,
            ));
            output::success_line(crate::install_ui::terminal_line!(
                "Added {} to target {}",
                install_ui::bold(&package.product.name),
                install_ui::bold(target_name),
            ));
            for module in &package.product.targets {
                println!("  import {}", install_ui::bold(module));
            }
            if package.request.ver_meta.has_security_issues() {
                crate::commands::add::print_install_security_warnings(
                    &package.request.name.scoped(),
                    package.request.version,
                    package.request.ver_meta,
                );
            }
            if options.audit_after_install {
                let summary = crate::commands::audit::summarize_registry_install(
                    &package.request.name.scoped(),
                    package.request.version,
                    package.request.ver_meta,
                );
                crate::commands::audit::print_install_summary(&summary, false);
            }
        }
    }

    let mut report = if package_reports.len() == 1 {
        package_reports[0].clone()
    } else {
        serde_json::json!({
            "success": true,
            "mode": "registry",
        })
    };
    report["packages"] = serde_json::Value::Array(package_reports);
    if let Some(setup) = registry_setup {
        report["registry_setup"] = setup.to_json();
    }
    if let Some(link) = xcode_link {
        report["project_type"] = serde_json::json!("xcode");
        report["wrapper_package"] = serde_json::json!("Packages/LPMDependencies");
        report["xcode_target"] = serde_json::json!(link.target_name);
    }
    Ok(report)
}

// the legacy `parse_package_spec` was deleted. Its replacement
// is `crate::save_spec::parse_user_save_intent`, which returns a strongly
// typed `UserSaveIntent` instead of `(String, String)`. The Swift routing
// site in `run_add_packages` calls `intent_to_range_string` directly to get
// a range string for metadata fetching.
//
// See `crate::save_spec` for the parser tests; the old in-file
// `parse_spec_*` tests were superseded by `save_spec::tests::parse_*`
// which cover the same matrix without the legacy `*`-default behavior.

/// Render a [`UserSaveIntent`] back to a string range for the legacy
/// metadata-fetch path. Used at the Swift ecosystem routing site only;
/// the manifest-write path uses [`SaveSpecDecision`] directly.
pub(super) fn intent_to_range_string(intent: &crate::save_spec::UserSaveIntent) -> String {
    use crate::save_spec::UserSaveIntent;
    match intent {
        UserSaveIntent::Bare | UserSaveIntent::Wildcard => "*".to_string(),
        UserSaveIntent::Exact(s)
        | UserSaveIntent::Range(s)
        | UserSaveIntent::DistTag(s)
        | UserSaveIntent::Workspace(s) => s.clone(),
    }
}

pub(super) fn swift_requirement_from_intent(
    intent: &crate::save_spec::UserSaveIntent,
    resolved_version: &str,
    save_flags: crate::save_spec::SaveFlags,
) -> Result<crate::swift_manifest::SwiftRequirement, LpmError> {
    use crate::save_spec::{SavePrefix, UserSaveIntent};
    use crate::swift_manifest::SwiftRequirement;

    let parsed = lpm_semver::Version::parse(resolved_version)?;
    let exact = matches!(intent, UserSaveIntent::Exact(_))
        || (!matches!(intent, UserSaveIntent::Range(_) | UserSaveIntent::Wildcard)
            && (save_flags.exact
                || save_flags.save_prefix == Some(SavePrefix::Empty)
                || parsed.is_prerelease()));
    if exact {
        return Ok(SwiftRequirement::Exact(resolved_version.to_string()));
    }

    let tilde = matches!(intent, UserSaveIntent::Range(range) if range.starts_with('~'))
        || (!matches!(intent, UserSaveIntent::Range(_) | UserSaveIntent::Wildcard)
            && (save_flags.tilde || save_flags.save_prefix == Some(SavePrefix::Tilde)));
    if tilde {
        return Ok(SwiftRequirement::UpToNextMinor {
            lower: resolved_version.to_string(),
            upper: format!("{}.{}.0", parsed.major(), parsed.minor().saturating_add(1)),
        });
    }

    if matches!(intent, UserSaveIntent::Range(range) if !range.starts_with('^'))
        || matches!(intent, UserSaveIntent::Wildcard)
    {
        return Ok(SwiftRequirement::Exact(resolved_version.to_string()));
    }

    Ok(SwiftRequirement::UpToNextMajor(
        resolved_version.to_string(),
    ))
}

/// Resolve the user-specified version range against a package's available versions.
///
/// When the user specifies a version (e.g., `@1.0.0` or `@^2.0.0`), find the best
/// matching version from metadata. When no version is specified (`*`), fall back to
/// `latest_ver`.
///
/// Returns the resolved version string.
pub(super) fn resolve_version_from_spec<'a>(
    range_spec: &str,
    metadata: &'a lpm_registry::PackageMetadata,
    latest_ver: &'a str,
) -> Result<&'a str, LpmError> {
    // If no version specified (wildcard), use latest
    if range_spec == "*" {
        return Ok(latest_ver);
    }

    if let Some(tagged_version) = metadata.dist_tags.get(range_spec) {
        return Ok(tagged_version.as_str());
    }

    let range = lpm_semver::VersionReq::parse(range_spec).map_err(|_| {
        LpmError::InvalidVersionRange(format!("invalid version range: {range_spec}"))
    })?;

    // Parse all available versions and find the best match
    let mut parsed_versions: Vec<(lpm_semver::Version, &str)> = metadata
        .versions
        .keys()
        .filter_map(|v_str| {
            lpm_semver::Version::parse(v_str)
                .ok()
                .map(|v| (v, v_str.as_str()))
        })
        .collect();

    // Sort so max_satisfying-style logic works
    parsed_versions.sort_by(|a, b| a.0.cmp(&b.0));

    // Find the highest version satisfying the range
    let best = parsed_versions.iter().rev().find(|(v, _)| range.matches(v));

    match best {
        Some((_, ver_str)) => Ok(ver_str),
        None => Err(LpmError::NotFound(format!(
            "no version matching {range_spec} found (available: {})",
            metadata
                .versions
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::save_spec::{SaveFlags, SavePrefix, UserSaveIntent};
    use crate::swift_manifest::SwiftRequirement;

    #[test]
    fn explicit_swift_version_uses_an_exact_requirement() {
        let requirement = swift_requirement_from_intent(
            &UserSaveIntent::Exact("1.2.3".into()),
            "1.2.3",
            SaveFlags::default(),
        )
        .unwrap();

        assert_eq!(requirement, SwiftRequirement::Exact("1.2.3".into()));
    }

    #[test]
    fn swift_tilde_flag_uses_a_next_minor_requirement() {
        let requirement = swift_requirement_from_intent(
            &UserSaveIntent::Bare,
            "1.2.3",
            SaveFlags {
                save_prefix: Some(SavePrefix::Tilde),
                ..SaveFlags::default()
            },
        )
        .unwrap();

        assert_eq!(
            requirement,
            SwiftRequirement::UpToNextMinor {
                lower: "1.2.3".into(),
                upper: "1.3.0".into(),
            }
        );
    }

    #[test]
    fn swift_prerelease_dist_tag_is_pinned_exactly() {
        let requirement = swift_requirement_from_intent(
            &UserSaveIntent::DistTag("beta".into()),
            "2.0.0-beta.1",
            SaveFlags::default(),
        )
        .unwrap();

        assert_eq!(requirement, SwiftRequirement::Exact("2.0.0-beta.1".into()));
    }
}
