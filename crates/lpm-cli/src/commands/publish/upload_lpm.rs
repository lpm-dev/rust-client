use super::swift::extract_swift_metadata;
use crate::commands::publish_common::{self, TarballFile};
use crate::{install_ui, quality};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;

/// Publish to the LPM registry (existing behavior).
#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_to_lpm(
    client: &RegistryClient,
    name: &str,
    version: &str,
    readme: &Option<String>,
    tarball_data: &std::sync::Arc<Vec<u8>>,
    tarball_files: &[TarballFile],
    package_json_size_override: Option<u64>,
    version_data: &serde_json::Value,
    quality_result: &Option<quality::QualityResult>,
    lpm_config: &Option<serde_json::Value>,
    provided_otp: Option<&str>,
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
        install_ui::warn_line(crate::install_ui::terminal_line!(
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
    let otp_code: Option<String> = if let Some(code) = provided_otp {
        if !is_valid_otp(code) {
            return Err(LpmError::Registry(
                "--otp must be exactly six ASCII digits".into(),
            ));
        }
        Some(code.to_owned())
    } else if whoami.mfa_enabled == Some(true) {
        if json_output {
            return Err(LpmError::Registry(
                "2FA required in JSON mode — pass --otp <code> or use a CI token".into(),
            ));
        }
        let code: String = cliclack::input("Enter 2FA code")
            .validate(|input: &String| {
                if is_valid_otp(input) {
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

    let packed_size = |file: &TarballFile| {
        if file.path == "package.json" {
            package_json_size_override.unwrap_or(file.size)
        } else {
            file.size
        }
    };
    lpm_version["_npmPackMeta"] = serde_json::json!({
        "files": tarball_files.iter().map(|f| {
            serde_json::json!({
                "path": f.path,
                "size": packed_size(f),
            })
        }).collect::<Vec<_>>(),
        "unpackedSize": tarball_files.iter().map(packed_size).sum::<u64>(),
        "fileCount": tarball_files.len(),
    });

    // Read lpm.config.json for version payload
    if let Some(config) = lpm_config {
        lpm_version["_lpmConfig"] = config.clone();
    }

    if detected_ecosystem != "js" {
        lpm_version["_ecosystem"] = serde_json::json!(detected_ecosystem);
    }

    // For Swift: embed normalized metadata from the manifest extracted earlier
    if let Some(manifest) = swift_manifest {
        lpm_version["_swiftManifest"] = extract_swift_metadata(manifest);
    }

    let tarball_key = format!(
        "{}-{}.tgz",
        name.replace('/', "-").replace('@', ""),
        version
    );
    let mut fields = serde_json::Map::with_capacity(7);
    fields.insert("_id".into(), serde_json::json!(name));
    fields.insert("name".into(), serde_json::json!(name));
    fields.insert(
        "description".into(),
        lpm_version
            .get("description")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    );
    fields.insert(
        "readme".into(),
        readme.as_ref().map_or(serde_json::Value::Null, |value| {
            serde_json::Value::String(value.clone())
        }),
    );
    fields.insert("_ecosystem".into(), serde_json::json!(detected_ecosystem));
    fields.insert("dist-tags".into(), serde_json::json!({"latest": version}));
    fields.insert("versions".into(), serde_json::json!({version: lpm_version}));
    let payload = publish_common::prepare_json_publish_body(
        fields,
        &tarball_key,
        "application/gzip",
        tarball_data,
        None,
    )?;

    let encoded_name = urlencoding::encode(name);
    client
        .publish_package(
            &encoded_name,
            payload.replayable(),
            otp_code.as_deref(),
            tarball_data.len(),
        )
        .await
}

fn is_valid_otp(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::is_valid_otp;

    #[test]
    fn lpm_publish_otp_accepts_exactly_six_ascii_digits() {
        assert!(is_valid_otp("123456"));
    }

    #[test]
    fn lpm_publish_otp_rejects_invalid_codes() {
        for code in ["12345", "1234567", "１２３４５６", "12345a"] {
            assert!(!is_valid_otp(code), "unexpected valid OTP: {code}");
        }
    }
}
