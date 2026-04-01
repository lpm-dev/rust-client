use crate::output;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::time::Instant;

pub async fn run(
    client: &RegistryClient,
    package: &str,
    version: Option<&str>,
    output_dir: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let name = PackageName::parse(package)?;
    let start = Instant::now();

    // Step 1: Fetch metadata
    let spinner = if !json_output {
        let s = cliclack::spinner();
        s.start(format!("Fetching metadata for {name}..."));
        Some(s)
    } else {
        None
    };

    let metadata = client.get_package_metadata(&name).await?;

    // Resolve version
    let version_key = version
        .map(|v| v.to_string())
        .or_else(|| metadata.latest_version_tag().map(|s| s.to_string()))
        .ok_or_else(|| LpmError::NotFound(format!("no versions found for {name}")))?;

    let ver = metadata
        .version(&version_key)
        .ok_or_else(|| LpmError::NotFound(format!("version {version_key} not found for {name}")))?;

    let tarball_url = ver
        .tarball_url()
        .ok_or_else(|| LpmError::Registry(format!("no tarball URL for {name}@{version_key}")))?;

    let integrity_str = ver.integrity();

    if let Some(s) = spinner {
        s.stop(format!(
            "Resolved {} {}",
            name.bold(),
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

    let tarball_data = client.download_tarball(tarball_url).await?;
    let size = tarball_data.len();

    if let Some(s) = spinner {
        s.stop(format!(
            "Downloaded {} ({})",
            format!("{name}@{version_key}").bold(),
            format_bytes(size).dimmed()
        ));
    }

    // Step 3: Verify integrity
    let integrity_verified = if let Some(sri) = integrity_str {
        let spinner = if !json_output {
            let s = cliclack::spinner();
            s.start("Verifying integrity...");
            Some(s)
        } else {
            None
        };

        lpm_extractor::verify_integrity(&tarball_data, sri)?;

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
    let target_dir = output_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

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
        let json = serde_json::json!({
            "success": true,
            "package": name.to_string(),
            "version": version_key,
            "size_bytes": size,
            "integrity_verified": integrity_verified,
            "output_dir": target_dir.display().to_string(),
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
