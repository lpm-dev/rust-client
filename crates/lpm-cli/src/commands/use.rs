use crate::output;
use lpm_common::LpmError;
use lpm_common::color::Painted;

/// Handle `lpm use` subcommands: install, list, pin.
///
/// `lpm use` manages Node.js runtime versions for the project. Env-vars
/// management was split into its own top-level command (`lpm env`) — see
/// [`crate::commands::env`].
pub async fn run(
    action: &str,
    spec: Option<&str>,
    project_dir: &std::path::Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| LpmError::Network(format!("failed to create HTTP client: {e}")))?;

    match action {
        "install" | "i" => {
            let spec = spec.ok_or_else(|| {
                LpmError::Script("missing version spec. Usage: lpm use node@22".into())
            })?;

            let (runtime, version_spec) = parse_runtime_spec(spec);
            if runtime != "node" {
                return Err(LpmError::Script(format!(
                    "runtime '{runtime}' not yet supported. Currently supported: node"
                )));
            }

            let platform = lpm_runtime::platform::Platform::current()?;
            output::info(&format!(
                "resolving node@{} for {}...",
                version_spec, platform
            ));

            let releases = lpm_runtime::node::fetch_index(&http_client).await?;
            let release =
                lpm_runtime::node::resolve_version(&releases, &version_spec).ok_or_else(|| {
                    LpmError::Script(format!(
                        "no node.js release found matching '{version_spec}'"
                    ))
                })?;

            let version = release.version_bare().to_string();

            if lpm_runtime::node::is_installed(&version) {
                if json_output {
                    println!(
                        "{}",
                        serde_json::json!({"success": true, "status": "already_installed", "version": version})
                    );
                } else {
                    output::success(&format!("Node.js {} is already installed", version.bold()));
                }
                return Ok(());
            }

            output::info(&format!(
                "downloading Node.js {}...",
                release.version.bold()
            ));

            let installed =
                lpm_runtime::download::install_node(&http_client, &release, &platform).await?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "status": "installed", "version": installed})
                );
            } else {
                output::success(&format!("Node.js {} installed", installed.bold()));
                let bin_dir = lpm_runtime::node::node_bin_dir(&installed)?;
                println!("  {} {}", "location:".dimmed(), bin_dir.display());
            }
        }

        "list" | "ls" => {
            let filter_runtime = spec.unwrap_or("node");
            if filter_runtime != "node" {
                return Err(LpmError::Script(format!(
                    "runtime '{filter_runtime}' not yet supported"
                )));
            }

            let versions = lpm_runtime::node::list_installed()?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"success": true, "runtime": "node", "versions": versions})
                    )
                    .unwrap()
                );
            } else if versions.is_empty() {
                output::info("No Node.js versions installed via LPM");
                println!("  Run {} to install one", "lpm use node@22".cyan());
            } else {
                output::info(&format!("Installed Node.js versions ({})", versions.len()));
                for v in &versions {
                    println!("  {} {v}", "●".green());
                }
            }
        }

        "pin" => {
            let spec = spec.ok_or_else(|| {
                LpmError::Script("missing version. Usage: lpm use pin node@22.5.0".into())
            })?;

            let (runtime, version_spec) = parse_runtime_spec(spec);
            if runtime != "node" {
                return Err(LpmError::Script(format!(
                    "runtime '{runtime}' not yet supported"
                )));
            }

            lpm_runtime::node::validate_version_spec(&version_spec)?;

            let pinned_version = resolve_pinned_node_version(&version_spec);

            // Warn if the version is not currently installed
            if !json_output && !lpm_runtime::node::is_installed(&pinned_version) {
                output::warn(&format!(
                    "node@{} is not currently installed. Run `lpm use node@{}` to install it",
                    version_spec, version_spec
                ));
            }

            write_node_pin(project_dir, &pinned_version)?;

            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"success": true, "pinned": {"node": pinned_version}})
                );
            } else {
                output::success(&format!(
                    "Pinned node@{} in lpm.json",
                    pinned_version.bold()
                ));
            }
        }

        _ => {
            return Err(LpmError::Script(format!(
                "unknown action: '{action}'. Available: install, list, pin"
            )));
        }
    }

    Ok(())
}

fn parse_runtime_spec(spec: &str) -> (String, String) {
    if let Some((runtime, version)) = spec.split_once('@') {
        (runtime.to_string(), version.to_string())
    } else {
        // No @ sign — assume it's a node version
        ("node".to_string(), spec.to_string())
    }
}

fn select_pinned_node_version(version_spec: &str, installed: &[String]) -> String {
    lpm_runtime::node::find_matching_installed(version_spec, installed)
        .unwrap_or_else(|| version_spec.to_string())
}

fn resolve_pinned_node_version(version_spec: &str) -> String {
    lpm_runtime::node::list_installed().ok().map_or_else(
        || version_spec.to_string(),
        |installed| select_pinned_node_version(version_spec, &installed),
    )
}

fn write_node_pin(project_dir: &std::path::Path, node_version: &str) -> Result<(), LpmError> {
    let lpm_json_path = project_dir.join("lpm.json");
    let mut config: serde_json::Value = if lpm_json_path.exists() {
        let content = std::fs::read_to_string(&lpm_json_path)?;
        serde_json::from_str(&content)
            .map_err(|e| LpmError::Script(format!("failed to parse lpm.json: {e}")))?
    } else {
        serde_json::json!({})
    };

    if config.get("runtime").is_none() {
        config["runtime"] = serde_json::json!({});
    }
    config["runtime"]["node"] = serde_json::Value::String(node_version.to_string());

    let content = serde_json::to_string_pretty(&config)
        .map_err(|e| LpmError::Script(format!("failed to serialize lpm.json: {e}")))?
        + "\n";

    let tmp_path = lpm_json_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &content)?;
    std::fs::rename(&tmp_path, &lpm_json_path)?;
    Ok(())
}

/// Validate a pin version string.
/// Must satisfy the runtime layer's safe version-spec grammar.
#[cfg(test)]
fn is_valid_pin_version(v: &str) -> bool {
    lpm_runtime::node::validate_version_spec(v).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_pin_versions() {
        assert!(is_valid_pin_version("22.5.0"));
        assert!(is_valid_pin_version("22"));
        assert!(is_valid_pin_version("lts"));
        assert!(is_valid_pin_version("latest"));
        assert!(is_valid_pin_version("22.0.0-rc.1"));
        assert!(is_valid_pin_version("v20_lts"));
        assert!(is_valid_pin_version("^20"));
        assert!(is_valid_pin_version(">=20.0.0 <22.0.0"));
    }

    #[test]
    fn invalid_pin_versions() {
        assert!(!is_valid_pin_version("../../etc"));
        assert!(!is_valid_pin_version(""));
        assert!(!is_valid_pin_version("22; rm -rf /"));
        assert!(!is_valid_pin_version("path/to/node"));
        assert!(!is_valid_pin_version("22\n23"));
        assert!(!is_valid_pin_version("node@22")); // @ is not allowed
    }

    #[test]
    fn pin_prefers_highest_matching_installed_version() {
        let installed = vec![
            "22.12.0".to_string(),
            "22.8.0".to_string(),
            "20.18.0".to_string(),
        ];

        assert_eq!(select_pinned_node_version("22", &installed), "22.12.0");
        assert_eq!(
            select_pinned_node_version(">=20.0.0 <22.0.0", &installed),
            "20.18.0"
        );
    }

    #[test]
    fn pin_keeps_alias_when_it_cannot_resolve_locally() {
        let installed = vec!["22.12.0".to_string()];

        assert_eq!(select_pinned_node_version("lts", &installed), "lts");
    }

    #[test]
    fn atomic_write_produces_correct_content_and_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_json_path = dir.path().join("lpm.json");

        // Simulate the atomic write path from the pin logic
        let mut config = serde_json::json!({});
        config["runtime"] = serde_json::json!({});
        config["runtime"]["node"] = serde_json::Value::String("22.5.0".to_string());

        let content = serde_json::to_string_pretty(&config).unwrap() + "\n";

        let tmp_path = lpm_json_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &content).unwrap();
        std::fs::rename(&tmp_path, &lpm_json_path).unwrap();

        // Verify content is correct
        let written = std::fs::read_to_string(&lpm_json_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["runtime"]["node"], "22.5.0");

        // Verify trailing newline
        assert!(
            written.ends_with('\n'),
            "lpm.json must end with a trailing newline"
        );

        // Verify no temp file remains
        assert!(
            !tmp_path.exists(),
            "temporary .json.tmp file should not remain after atomic rename"
        );
    }

    #[test]
    fn atomic_write_preserves_existing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let lpm_json_path = dir.path().join("lpm.json");

        // Pre-existing lpm.json with other fields
        let existing = serde_json::json!({
            "name": "my-project",
            "runtime": { "node": "20.0.0" }
        });
        std::fs::write(
            &lpm_json_path,
            serde_json::to_string_pretty(&existing).unwrap() + "\n",
        )
        .unwrap();

        // Simulate pin update
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&lpm_json_path).unwrap()).unwrap();
        config["runtime"]["node"] = serde_json::Value::String("22.5.0".to_string());

        let content = serde_json::to_string_pretty(&config).unwrap() + "\n";
        let tmp_path = lpm_json_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &content).unwrap();
        std::fs::rename(&tmp_path, &lpm_json_path).unwrap();

        let written = std::fs::read_to_string(&lpm_json_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(parsed["name"], "my-project");
        assert_eq!(parsed["runtime"]["node"], "22.5.0");
        assert!(written.ends_with('\n'));
    }
}
