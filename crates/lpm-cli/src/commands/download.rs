use crate::commands::install::{
    NpmFirewallMaterializationPackage, prepare_npm_firewall_materialization_preflight,
    registry_materialization_route_is_public_npm,
    run_prepared_npm_firewall_materialization_preflight,
};
use crate::commands::registry_reads::{
    RoutedPackageRef, fetch_routed_package_metadata, normalize_package_version_input,
    prepare_routed_read_context,
};
use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    package: &str,
    version: Option<&str>,
    output_dir: Option<&str>,
    allow_unverified: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let (package, version) = normalize_package_version_input("download", package, version)?;
    let context =
        prepare_routed_read_context(client, project_dir, &[package.to_string()], json_output)?;
    let start = Instant::now();

    if !json_output {
        install_ui::phase_line(install_ui::TerminalLine::new("Resolving ").field(package));
    }

    let (package_ref, metadata) = fetch_routed_package_metadata(&context, package).await?;
    let package_name = metadata.name.clone();

    let version_key = match version {
        Some(spec) => metadata.resolve_version_spec(spec)?,
        None => metadata
            .latest_version_tag()
            .map(str::to_string)
            .ok_or_else(|| LpmError::NotFound(format!("no versions found for {package_name}")))?,
    };

    let ver = metadata.version(&version_key).ok_or_else(|| {
        LpmError::NotFound(format!(
            "version {version_key} not found for {package_name}"
        ))
    })?;

    let tarball_url = ver.tarball_url().ok_or_else(|| {
        LpmError::Registry(format!("no tarball URL for {package_name}@{version_key}"))
    })?;

    let integrity_str = ver.integrity_or_shasum();

    let firewall_packages = match &package_ref {
        RoutedPackageRef::Registry(route_name)
            if registry_materialization_route_is_public_npm(
                &context.route_table,
                &context.client,
                route_name,
            ) =>
        {
            vec![NpmFirewallMaterializationPackage::new(
                &package_name,
                &version_key,
                integrity_str.as_deref(),
                metadata.time.get(&version_key).map(String::as_str),
            )]
        }
        _ => Vec::new(),
    };
    let firewall_preflight = prepare_npm_firewall_materialization_preflight(
        project_dir,
        &firewall_packages,
        json_output,
    )?;

    if !json_output {
        let download_message = install_ui::TerminalLine::new("Downloading ")
            .field(&package_name)
            .text("@")
            .field(&version_key);
        install_ui::phase_line(install_ui::with_firewall_badge(
            download_message,
            firewall_preflight.is_active(),
        ));
    }

    let firewall_json = run_prepared_npm_firewall_materialization_preflight(
        &context.client,
        firewall_preflight,
        json_output,
    )
    .await?;

    let downloaded = context
        .client
        .download_tarball_routed(&context.route_table, &package_ref.route_name(), tarball_url)
        .await?;
    let tarball_data = std::fs::read(downloaded.file.path()).map_err(LpmError::Io)?;
    let size = tarball_data.len();

    // Step 3: Verify integrity. Refuse-by-default for the audit-use
    // posture: `lpm download` is documented as the tool for
    // inspecting a package's contents, and silently accepting bytes
    // for which the registry shipped no SRI defeats that purpose.
    // `--allow-unverified` explicitly waives the gate for legacy
    // sources (mirrors, GitHub release assets) that genuinely lack
    // integrity.
    if integrity_str.is_none() && !allow_unverified {
        return Err(LpmError::Registry(format!(
            "{package_name}@{version_key}: registry returned no integrity hash; \
             refusing to extract an unverified tarball. Re-run with \
             --allow-unverified if you accept the risk (audit use \
             should not normally take that path).",
        )));
    }
    let integrity_verified = if let Some(sri) = integrity_str.as_ref() {
        lpm_extractor::verify_integrity(&tarball_data, sri.as_ref())?;

        if !json_output {
            install_ui::done_line(
                install_ui::TerminalLine::new("Verified integrity ").field(&short_integrity(sri)),
            );
        }
        true
    } else {
        if !json_output {
            install_ui::warn("No integrity hash available — skipping verification");
        }
        false
    };

    // Step 4: Extract
    let target_dir = output_dir.map_or_else(|| PathBuf::from("."), PathBuf::from);

    let files = lpm_extractor::extract_tarball(&tarball_data, &target_dir)?;

    let elapsed = start.elapsed();

    if json_output {
        // Resolve to an absolute path now that extraction has created the
        // directory. Fall back to the lexical form if canonicalize fails
        // (e.g., target_dir was deleted out from under us mid-run).
        let absolute_output_dir = target_dir.canonicalize().map_or_else(
            |_| target_dir.display().to_string(),
            |p| p.display().to_string(),
        );
        let mut json = serde_json::json!({
            "success": true,
            "package": package_name,
            "version": version_key,
            "tarball_url": tarball_url,
            "integrity": integrity_str,
            "integrity_verified": integrity_verified,
            "size_bytes": size,
            "output_dir": absolute_output_dir,
            "files_extracted": files.len(),
            "elapsed_secs": (elapsed.as_millis() as f64) / 1000.0,
        });
        if let Some(firewall_json) = firewall_json {
            json["firewall"] = firewall_json;
        }
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        eprintln!(
            "{}",
            crate::install_ui::terminal_line!(
                "    {} {}",
                install_ui::dim(&format!("{:<16}", "output:")),
                install_ui::yellow(&target_dir.display().to_string())
            )
        );
        eprintln!(
            "{}",
            crate::install_ui::terminal_line!(
                "    {} {}",
                install_ui::dim(&format!("{:<16}", "files extracted:")),
                files.len()
            )
        );
        eprintln!(
            "{}",
            crate::install_ui::terminal_line!(
                "    {} {}",
                install_ui::dim(&format!("{:<16}", "size:")),
                format_bytes(size)
            )
        );
        eprintln!();

        // Show extracted files summary
        if files.len() <= 20 {
            for f in &files {
                eprintln!(
                    "{}",
                    crate::install_ui::terminal_line!(
                        "    {}",
                        install_ui::dim(&f.display().to_string())
                    )
                );
            }
        } else {
            for f in files.iter().take(15) {
                eprintln!(
                    "{}",
                    crate::install_ui::terminal_line!(
                        "    {}",
                        install_ui::dim(&f.display().to_string())
                    )
                );
            }
            eprintln!(
                "{}",
                crate::install_ui::terminal_line!(
                    "    {}",
                    install_ui::dim(&format!("… and {} more files", files.len() - 15))
                )
            );
        }

        eprintln!();
        let duration = install_ui::format_duration(elapsed);
        install_ui::done_line(
            install_ui::TerminalLine::new("Done · tarball extracted in ").green(&duration),
        );
    }

    Ok(())
}

fn short_integrity(integrity: &str) -> String {
    const KEEP: usize = 10;
    if integrity.chars().count() <= KEEP * 2 + 3 {
        return integrity.to_string();
    }
    let prefix: String = integrity.chars().take(KEEP).collect();
    let suffix: String = integrity
        .chars()
        .rev()
        .take(KEEP)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}…{suffix}")
}

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
