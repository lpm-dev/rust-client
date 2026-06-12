use super::swift::extract_swift_metadata;
use crate::commands::publish_common::TarballFile;
use crate::{install_ui, quality};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::path::Path;

/// Publish to the LPM registry (existing behavior).
#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_to_lpm(
    client: &RegistryClient,
    project_dir: &Path,
    name: &str,
    version: &str,
    readme: &Option<String>,
    tarball_data: &[u8],
    tarball_files: &[TarballFile],
    version_data: &serde_json::Value,
    quality_result: &Option<quality::QualityResult>,
    json_output: bool,
    detected_ecosystem: &str,
    swift_manifest: &Option<serde_json::Value>,
) -> Result<serde_json::Value, LpmError> {
    // Credentials must not travel over plain HTTP for LPM publish.
    let registry_url = client.base_url();
    if !registry_url.starts_with("https://")
        && !registry_url.starts_with("http://localhost")
        && !registry_url.starts_with("http://127.0.0.1")
    {
        return Err(LpmError::Registry(format!(
            "refusing to publish over HTTP to {registry_url} — credentials require HTTPS"
        )));
    }

    // Make non-default LPM registry targets visible in human output.
    if !registry_url.starts_with("https://lpm.dev")
        && !registry_url.starts_with("http://localhost")
        && !registry_url.starts_with("http://127.0.0.1")
        && !json_output
    {
        install_ui::detail("");
        install_ui::warn(&format!(
            "Publishing to non-default registry: {}",
            install_ui::url(registry_url)
        ));
    }

    // Verify token has publish scope
    let whoami = client
        .whoami()
        .await
        .map_err(|e| LpmError::Registry(format!("authentication failed: {e}")))?;

    // 2FA check — prompt before uploading
    let otp_code: Option<String> = if whoami.mfa_enabled == Some(true) {
        if json_output {
            return Err(LpmError::Registry(
                "2FA required but running in JSON mode — use --token with a CI token instead"
                    .into(),
            ));
        }
        let code: String = cliclack::input("Enter 2FA code")
            .validate(|input: &String| {
                if input.len() == 6 && input.chars().all(|c| c.is_ascii_digit()) {
                    Ok(())
                } else {
                    Err("Must be a 6-digit code")
                }
            })
            .interact()
            .map_err(|e| LpmError::Registry(e.to_string()))?;
        Some(code)
    } else {
        None
    };

    // Build LPM version data (add LPM-specific fields)
    let mut lpm_version = version_data.clone();

    if let Some(qr) = quality_result {
        lpm_version["_qualityChecks"] =
            serde_json::to_value(&qr.checks).unwrap_or(serde_json::json!(null));
        lpm_version["_qualityMeta"] = serde_json::json!({
            "score": qr.score,
            "maxScore": qr.max_score,
            "ecosystem": "js",
        });
    }

    lpm_version["_npmPackMeta"] = serde_json::json!({
        "files": tarball_files.iter().map(|f| {
            serde_json::json!({
                "path": f.path,
                "size": f.size,
            })
        }).collect::<Vec<_>>(),
        "unpackedSize": tarball_files.iter().map(|f| f.size).sum::<u64>(),
        "fileCount": tarball_files.len(),
    });

    // Read lpm.config.json for version payload
    let lpm_config_path = project_dir.join("lpm.config.json");
    if lpm_config_path.exists()
        && let Ok(config_str) = std::fs::read_to_string(&lpm_config_path)
        && let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_str)
    {
        lpm_version["_lpmConfig"] = config;
    }

    if detected_ecosystem != "js" {
        lpm_version["_ecosystem"] = serde_json::json!(detected_ecosystem);
    }

    // For Swift: embed normalized metadata from the manifest extracted earlier
    if let Some(manifest) = swift_manifest {
        lpm_version["_swiftManifest"] = extract_swift_metadata(manifest);
    }

    // Pre-allocate the base64 buffer from the encoded-size estimate.
    let tarball_key = format!(
        "{}-{}.tgz",
        name.replace('/', "-").replace('@', ""),
        version
    );
    let tarball_mb = tarball_data.len() / (1024 * 1024);
    if tarball_mb > 50 && !json_output {
        let peak_mb = tarball_data.len() * 4 / 3 / (1024 * 1024) + tarball_mb;
        install_ui::warn(&format!(
            "Large tarball ({tarball_mb}MB). This will require ~{peak_mb}MB of memory."
        ));
    }
    let mut tarball_base64 = String::with_capacity(tarball_data.len() * 4 / 3 + 4);
    BASE64.encode_string(tarball_data, &mut tarball_base64);

    let payload = serde_json::json!({
        "_id": name,
        "name": name,
        "description": lpm_version.get("description"),
        "readme": readme,
        "_ecosystem": detected_ecosystem,
        "dist-tags": {
            "latest": version,
        },
        "versions": {
            version: lpm_version,
        },
        "_attachments": {
            tarball_key: {
                "content_type": "application/gzip",
                "data": tarball_base64,
                "length": tarball_data.len(),
            }
        },
    });

    let encoded_name = urlencoding::encode(name);
    client
        .publish_package(
            &encoded_name,
            &payload,
            otp_code.as_deref(),
            tarball_data.len(),
        )
        .await
}
