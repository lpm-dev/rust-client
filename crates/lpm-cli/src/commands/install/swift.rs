use super::*;

/// Install a Swift package via SE-0292 registry: edit Package.swift + resolve.
pub(super) async fn run_swift_install(
    project_dir: &Path,
    name: &lpm_common::PackageName,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
    yes: bool,
    json_output: bool,
    registry_url: &str,
) -> Result<(), LpmError> {
    use crate::swift_manifest;
    use crate::xcode_project;

    let se0292_id = swift_manifest::lpm_to_se0292_id(name);
    let product_name = ver_meta.swift_product_name().unwrap_or_else(|| &name.name);

    // Detect project type: SPM (Package.swift) vs Xcode (.xcodeproj)
    let manifest_path = swift_manifest::find_package_swift(project_dir);
    let xcodeproj_path = xcode_project::find_xcodeproj(project_dir);

    match (manifest_path, xcodeproj_path) {
        // Both exist or only SPM → use existing SPM flow
        (Some(manifest), _) => {
            run_swift_install_spm(
                project_dir,
                &manifest,
                name,
                version,
                ver_meta,
                &se0292_id,
                product_name,
                yes,
                json_output,
                registry_url,
            )
            .await
        }
        // Only Xcode project → new Xcode wrapper flow
        (None, Some(xcodeproj)) => {
            run_swift_install_xcode(
                project_dir,
                &xcodeproj,
                name,
                version,
                ver_meta,
                &se0292_id,
                product_name,
                json_output,
                registry_url,
            )
            .await
        }
        // Neither
        (None, None) => Err(LpmError::Registry(
            "No Package.swift or .xcodeproj found. Initialize a Swift project first.".into(),
        )),
    }
}

/// Install a Swift package into an SPM project.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_swift_install_spm(
    project_dir: &Path,
    manifest_path: &Path,
    name: &lpm_common::PackageName,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
    se0292_id: &str,
    product_name: &str,
    yes: bool,
    json_output: bool,
    registry_url: &str,
) -> Result<(), LpmError> {
    use crate::swift_manifest;

    let manifest_dir = manifest_path.parent().unwrap_or(project_dir);

    if !json_output {
        output::info_line(crate::install_ui::terminal_line!(
            "Installing {} via SE-0292 registry → {}",
            install_ui::bold(&name.scoped()),
            install_ui::dim(se0292_id),
        ));
    }

    // Detect targets
    let targets = swift_manifest::get_spm_targets(manifest_dir).unwrap_or_default();
    let target_name = match targets.as_slice() {
        [] => {
            return Err(LpmError::Registry(
                "No non-test targets found in Package.swift.".into(),
            ));
        }
        [target] => target.clone(),
        [first, ..] if yes => first.clone(),
        _ => {
            let mut sel = cliclack::select("Which target should use this dependency?");
            for (i, target) in targets.iter().enumerate() {
                sel = sel.item(
                    target.clone(),
                    lpm_common::sanitize_terminal_inline(target).into_owned(),
                    "",
                );
                if i == 0 {
                    sel = sel.initial_value(target.clone());
                }
            }
            sel.interact()
                .map_err(|e| LpmError::Registry(format!("prompt failed: {e}")))?
        }
    };

    // Edit Package.swift
    let edit = swift_manifest::add_registry_dependency(
        manifest_path,
        se0292_id,
        version,
        product_name,
        &target_name,
    )?;

    if edit.already_exists {
        if !json_output {
            output::info_line(crate::install_ui::terminal_line!(
                "{} is already in Package.swift",
                install_ui::dim(se0292_id)
            ));
        }
    } else if !json_output {
        output::success_line(crate::install_ui::terminal_line!(
            "Added .package(id: \"{}\", from: \"{}\")",
            se0292_id,
            version
        ));
        output::success_line(crate::install_ui::terminal_line!(
            "Added .product(name: \"{}\") to target {}",
            product_name,
            install_ui::bold(&target_name)
        ));
    }

    // Resolve
    let registry_setup = if !edit.already_exists {
        // Auto-configure registry scope if needed
        let setup = crate::commands::swift_registry::ensure_configured(
            registry_url,
            manifest_dir,
            json_output,
        )
        .await?;

        if !json_output {
            output::info("Resolving Swift packages...");
        }
        swift_manifest::run_swift_resolve(manifest_dir)?;
        Some(setup)
    } else {
        None
    };

    // Output
    if json_output {
        let mut json = serde_json::json!({
            "package": name.scoped(),
            "version": version,
            "mode": "registry",
            "se0292_id": se0292_id,
            "product_name": product_name,
            "target": target_name,
            "already_existed": edit.already_exists,
        });
        if let Some(setup) = registry_setup {
            json["registry_setup"] = setup.to_json();
        }
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if !edit.already_exists {
        println!();
        output::success_line(crate::install_ui::terminal_line!(
            "Installed {}@{} via SE-0292 registry",
            install_ui::bold(&name.scoped()),
            version,
        ));
        println!(
            "  import {} // in your Swift code",
            install_ui::bold(product_name)
        );
    }

    // Security check
    if ver_meta.has_security_issues() && !json_output {
        crate::commands::add::print_install_security_warnings(&name.scoped(), version, ver_meta);
    }

    if !json_output && !edit.already_exists {
        println!();
    }

    Ok(())
}

/// Install a Swift package into an Xcode app project via local wrapper package.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_swift_install_xcode(
    project_dir: &Path,
    xcodeproj_path: &Path,
    name: &lpm_common::PackageName,
    version: &str,
    ver_meta: &lpm_registry::VersionMetadata,
    se0292_id: &str,
    product_name: &str,
    json_output: bool,
    registry_url: &str,
) -> Result<(), LpmError> {
    use crate::swift_manifest;
    use crate::xcode_project;

    // Resolve the project root (xcodeproj's parent)
    let project_root = xcodeproj_path.parent().unwrap_or(project_dir);

    if !json_output {
        output::info_line(crate::install_ui::terminal_line!(
            "Installing {} via SE-0292 registry → {} (Xcode project)",
            install_ui::bold(&name.scoped()),
            install_ui::dim(se0292_id),
        ));
    }

    // Step 1: Ensure LPMDependencies wrapper package exists
    let wrapper = swift_manifest::ensure_wrapper_package(project_root)?;
    if wrapper.created && !json_output {
        output::success("Created Packages/LPMDependencies/ wrapper package");
    }

    // Step 2: Add the registry dependency to the wrapper Package.swift
    let edit = swift_manifest::add_wrapper_dependency(
        &wrapper.manifest_path,
        se0292_id,
        version,
        product_name,
    )?;

    if edit.already_exists {
        if !json_output {
            output::info_line(crate::install_ui::terminal_line!(
                "{} is already installed",
                install_ui::dim(se0292_id)
            ));
        }
    } else if !json_output {
        output::success_line(crate::install_ui::terminal_line!(
            "Added .package(id: \"{}\", from: \"{}\")",
            se0292_id,
            version,
        ));
    }

    // Step 3: Link to Xcode project (pbxproj editing — first install only)
    let link_result = xcode_project::link_local_package(
        xcodeproj_path,
        swift_manifest::LPM_DEPS_PACKAGE_NAME,
        swift_manifest::LPM_DEPS_REL_PATH,
    )?;

    if link_result.package_ref_added && !json_output {
        output::success_line(crate::install_ui::terminal_line!(
            "Linked LPMDependencies to Xcode target {}",
            install_ui::bold(&link_result.target_name),
        ));
    }

    // Step 4: Resolve Swift packages
    let registry_setup = if !edit.already_exists {
        // Auto-configure registry scope if needed
        let wrapper_dir = wrapper.manifest_path.parent().unwrap_or(project_root);
        let setup = crate::commands::swift_registry::ensure_configured(
            registry_url,
            wrapper_dir,
            json_output,
        )
        .await?;

        if !json_output {
            output::info("Resolving Swift packages...");
        }
        swift_manifest::run_swift_resolve(wrapper_dir)?;
        Some(setup)
    } else {
        None
    };

    // Step 5: Output
    if json_output {
        let mut json = serde_json::json!({
            "package": name.scoped(),
            "version": version,
            "mode": "registry",
            "project_type": "xcode",
            "se0292_id": se0292_id,
            "product_name": product_name,
            "wrapper_package": "Packages/LPMDependencies",
            "xcode_target": link_result.target_name,
            "already_existed": edit.already_exists,
        });
        if let Some(setup) = registry_setup {
            json["registry_setup"] = setup.to_json();
        }
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if !edit.already_exists {
        println!();
        output::success_line(crate::install_ui::terminal_line!(
            "Installed {}@{} via SE-0292 registry",
            install_ui::bold(&name.scoped()),
            version,
        ));
        println!(
            "  import {} // in your Swift code",
            install_ui::bold(product_name)
        );
    }

    // Security check
    if ver_meta.has_security_issues() && !json_output {
        crate::commands::add::print_install_security_warnings(&name.scoped(), version, ver_meta);
    }

    // Xcode warning (first link only)
    if link_result.package_ref_added && !json_output {
        println!();
        output::warn("If Xcode is open, close and reopen the project to pick up changes.");
    }

    if !json_output && !edit.already_exists {
        println!();
    }

    Ok(())
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
