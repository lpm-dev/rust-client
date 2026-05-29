use crate::commands::registry_reads::{fetch_routed_package_metadata, prepare_routed_read_context};
use crate::output;
use lpm_common::LpmError;
use lpm_common::color::Painted;
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
    let context =
        prepare_routed_read_context(client, project_dir, &[package.to_string()], json_output)?;
    let start = Instant::now();

    // Step 1: Fetch metadata
    let spinner = if !json_output {
        let s = cliclack::spinner();
        s.start(format!("Fetching metadata for {package}..."));
        Some(s)
    } else {
        None
    };

    let (package_ref, metadata) = fetch_routed_package_metadata(&context, package).await?;
    let package_name = metadata.name.clone();

    // Resolve version
    let version_key = version
        .map(|v| v.to_string())
        .or_else(|| metadata.latest_version_tag().map(|s| s.to_string()))
        .ok_or_else(|| LpmError::NotFound(format!("no versions found for {package_name}")))?;

    let ver = metadata.version(&version_key).ok_or_else(|| {
        LpmError::NotFound(format!(
            "version {version_key} not found for {package_name}"
        ))
    })?;

    let tarball_url = ver.tarball_url().ok_or_else(|| {
        LpmError::Registry(format!("no tarball URL for {package_name}@{version_key}"))
    })?;

    let integrity_str = ver.integrity_or_shasum();

    if let Some(s) = spinner {
        s.stop(format!(
            "Resolved {} {}",
            package_name.bold(),
            format!("v{version_key}").dimmed()
        ));
    }

    // Step 2: Download tarball
    let spinner = if !json_output {
        let s = cliclack::spinner();
        s.start("Downloading tarball...");
        Some(s)
    } else {
        None
    };

    let downloaded = context
        .client
        .download_tarball_routed(&context.route_table, &package_ref.route_name(), tarball_url)
        .await?;
    let tarball_data = std::fs::read(downloaded.file.path()).map_err(LpmError::Io)?;
    let size = tarball_data.len();

    if let Some(s) = spinner {
        s.stop(format!(
            "Downloaded {} ({})",
            format!("{package_name}@{version_key}").bold(),
            format_bytes(size).dimmed()
        ));
    }

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
        let spinner = if !json_output {
            let s = cliclack::spinner();
            s.start("Verifying integrity...");
            Some(s)
        } else {
            None
        };

        lpm_extractor::verify_integrity(&tarball_data, sri.as_ref())?;

        if let Some(s) = spinner {
            s.stop("Integrity verified ✓");
        }
        true
    } else {
        if !json_output {
            output::warn("No integrity hash available — skipping verification");
        }
        false
    };

    // Step 4: Extract
    let target_dir = output_dir.map_or_else(|| PathBuf::from("."), PathBuf::from);

    let spinner = if !json_output {
        let s = cliclack::spinner();
        s.start(format!("Extracting to {}...", target_dir.display()));
        Some(s)
    } else {
        None
    };

    let files = lpm_extractor::extract_tarball(&tarball_data, &target_dir)?;

    if let Some(s) = spinner {
        s.stop(format!(
            "Extracted {} files to {} in {:.1}s",
            files.len().to_string().bold(),
            target_dir.display().to_string().bold(),
            start.elapsed().as_secs_f64()
        ));
    }

    let elapsed = start.elapsed();

    if json_output {
        // Resolve to an absolute path now that extraction has created the
        // directory. Fall back to the lexical form if canonicalize fails
        // (e.g., target_dir was deleted out from under us mid-run).
        let absolute_output_dir = target_dir.canonicalize().map_or_else(
            |_| target_dir.display().to_string(),
            |p| p.display().to_string(),
        );
        let json = serde_json::json!({
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
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        // Show extracted files summary
        if files.len() <= 20 {
            for f in &files {
                println!("    {}", f.display().to_string().dimmed());
            }
        } else {
            for f in files.iter().take(15) {
                println!("    {}", f.display().to_string().dimmed());
            }
            println!(
                "    {}",
                format!("... and {} more files", files.len() - 15).dimmed()
            );
        }

        println!();
    }

    Ok(())
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
