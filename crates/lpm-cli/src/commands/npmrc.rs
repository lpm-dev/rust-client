use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
use std::path::Path;

/// Generate a read-only .npmrc token for local development.
///
/// Creates a scoped read-only token and writes it to the project's .npmrc.
/// Also ensures .npmrc is in .gitignore to prevent accidental commits.
///
/// Default: scoped config (`@lpm.dev:registry=`) — only LPM packages go through lpm.dev.
/// Use `--proxy` to route all npm traffic through lpm.dev (Pro/Org feature).
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    registry_url: &str,
    days: u32,
    proxy: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    let npmrc_path = project_dir.join(".npmrc");
    let gitignore_path = project_dir.join(".gitignore");

    if !pkg_json_path.exists() && !json_output {
        output::warn("No package.json found. Run this command in your project root.");
    }

    // Derive project name for the token label
    let project_name = if pkg_json_path.exists() {
        std::fs::read_to_string(&pkg_json_path)
            .ok()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
            .and_then(|v| v.get("name")?.as_str().map(|s| s.to_string()))
            .map(|name| {
                name.chars()
                    .map(|c| {
                        if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                            c
                        } else {
                            '-'
                        }
                    })
                    .collect::<String>()
            })
            .unwrap_or_else(|| "project".to_string())
    } else {
        "project".to_string()
    };

    if !json_output {
        output::info("Creating read-only token...");
    }

    // Create scoped read-only token via API
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Simple date: days since epoch → YYYY-MM-DD
    let days_since_epoch = now / 86400;
    let today = format!("{}", days_since_epoch); // Use epoch days as unique suffix
    let token_name = format!("npmrc-{project_name}-{today}");

    let body = serde_json::json!({
        "scope": "read",
        "name": token_name,
        "expiryDays": days,
    });

    let url = format!("{registry_url}/api/registry/-/token/create");
    let response = client
        .post_json_raw(&url, &body)
        .await
        .map_err(|e| LpmError::Registry(format!("failed to create token: {e}")))?;

    let response_json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| LpmError::Registry(format!("invalid response: {e}")))?;

    let read_token = response_json
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| LpmError::Registry("no token in response".into()))?
        .to_string();

    let expires_at = response_json
        .get("expiresAt")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if !json_output {
        output::success("Read-only token created.");
    }

    // Build .npmrc content
    let full_registry_url = if registry_url.ends_with("/api/registry") {
        registry_url.to_string()
    } else {
        format!("{registry_url}/api/registry")
    };
    let registry_host = full_registry_url.replace("https:", "").replace("http:", "");

    // Default: scoped (only @lpm.dev packages through lpm.dev, npm direct).
    // --proxy: route all traffic through lpm.dev (Pro/Org feature).
    let use_proxy = if proxy {
        // Check plan tier — proxy is a Pro/Org feature
        if !json_output {
            match client.whoami().await {
                Ok(info) => {
                    let tier = info.plan_tier.as_deref().unwrap_or("free");
                    if tier == "free" {
                        output::warn("Proxy mode routes all npm traffic through lpm.dev.");
                        output::warn(&format!(
                            "This is designed for Pro/Org accounts. Your plan: {}.",
                            tier.bold()
                        ));
                        output::info(
                            "Upgrade at https://lpm.dev/pricing for dependency analytics and org audit.",
                        );
                        println!();
                    }
                }
                Err(_) => {
                    // Can't check plan — proceed anyway (user explicitly asked for --proxy)
                }
            }
        }
        true
    } else if npmrc_path.exists() {
        // Check for existing custom registry — don't override it
        let existing = std::fs::read_to_string(&npmrc_path).unwrap_or_default();
        let has_custom_registry = existing.lines().any(|line| {
            line.starts_with("registry=")
                && !line.contains("registry.npmjs.org")
                && !line.contains("lpm.dev")
        });
        if has_custom_registry && !json_output {
            output::info("Found existing custom default registry. Using scoped mode.");
        }
        false // Always scoped when custom registry exists
    } else {
        false // Default: scoped
    };

    // Read existing .npmrc, strip old LPM lines
    let existing_content = if npmrc_path.exists() {
        let content = std::fs::read_to_string(&npmrc_path).unwrap_or_default();
        content
            .lines()
            .filter(|line| {
                !line.contains("@lpm.dev:registry") && !line.starts_with("registry=")
                    || !line.contains("lpm.dev")
                        && !line.contains("lpm.dev/api/registry/:_authToken")
                        && !line.contains("_authToken=lpm_")
                        && !line.contains("_authToken=${LPM_TOKEN}")
                        && !line.contains("# LPM Registry")
            })
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string()
    } else {
        String::new()
    };

    // Build new config
    let registry_line = if use_proxy {
        format!("registry={full_registry_url}")
    } else {
        format!("@lpm.dev:registry={full_registry_url}")
    };

    let lpm_config = format!(
        "# LPM Registry (generated by lpm npmrc — do not commit)\n{registry_line}\n{registry_host}/:_authToken={read_token}"
    );

    let final_content = if existing_content.is_empty() {
        format!("{lpm_config}\n")
    } else {
        format!("{existing_content}\n\n{lpm_config}\n")
    };

    std::fs::write(&npmrc_path, &final_content)?;

    // S6: Restrict .npmrc permissions to owner-only (contains auth tokens)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&npmrc_path, std::fs::Permissions::from_mode(0o600));
    }

    // Ensure .npmrc is in .gitignore
    let mut gitignore_updated = false;
    if gitignore_path.exists() {
        let gitignore = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        if !gitignore.lines().any(|line| line.trim() == ".npmrc") {
            let updated = format!("{}\n.npmrc\n", gitignore.trim_end());
            std::fs::write(&gitignore_path, updated)?;
            gitignore_updated = true;
        }
    } else {
        std::fs::write(&gitignore_path, ".npmrc\n")?;
        gitignore_updated = true;
    }

    // Output
    if json_output {
        let json = serde_json::json!({
            "success": true,
            "npmrc_path": npmrc_path.display().to_string(),
            "proxy": use_proxy,
            "expires_at": expires_at,
            "expiry_days": days,
            "gitignore_updated": gitignore_updated,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!();
        output::success(".npmrc configured with read-only LPM token.");
        if gitignore_updated {
            output::info(".npmrc added to .gitignore to prevent token leaks.");
        }
        if use_proxy {
            output::info("All packages (LPM + npm) will route through lpm.dev.");
            output::info("Note: First install may update resolved URLs in your lockfile.");
        } else {
            output::info("Only @lpm.dev packages will route through lpm.dev.");
        }
        if !expires_at.is_empty() {
            output::info(&format!("Token expires: {}", expires_at.dimmed()));
        }
        output::info("Run `lpm npmrc` again to refresh when expired.");
        println!();
    }

    Ok(())
}
