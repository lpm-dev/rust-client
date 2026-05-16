use crate::output;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use std::path::Path;
use std::time::Duration;

/// Initialize a new package.json for an LPM package.
pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    yes: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if pkg_json_path.exists() {
        return Err(LpmError::Registry("package.json already exists".into()));
    }

    let resolved_owner = resolve_owner_default(client).await;

    let (owner, name, version, description) = if yes {
        (
            resolved_owner,
            "package".to_string(),
            "1.0.0".to_string(),
            String::new(),
        )
    } else {
        let owner: String = cliclack::input("Owner (your username or org)")
            .default_input(&resolved_owner)
            .placeholder("username")
            .interact()
            .map_err(|e| LpmError::Registry(e.to_string()))?;

        let name: String = cliclack::input("Package name")
            .default_input("package")
            .placeholder("package")
            .interact()
            .map_err(|e| LpmError::Registry(e.to_string()))?;

        let version: String = cliclack::input("Version")
            .default_input("1.0.0")
            .placeholder("1.0.0")
            .interact()
            .map_err(|e| LpmError::Registry(e.to_string()))?;

        let description: String = cliclack::input("Description")
            .placeholder("A brief description of your package")
            .required(false)
            .interact()
            .map_err(|e| LpmError::Registry(e.to_string()))?;

        (owner, name, version, description)
    };

    let full_name = format!("@lpm.dev/{owner}.{name}");

    let mut pkg = serde_json::json!({
        "name": full_name,
        "version": version,
        "main": "dist/index.js",
        "types": "dist/index.d.ts",
        "type": "module",
        "license": "MIT",
        "files": ["dist"],
    });

    if !description.is_empty() {
        pkg["description"] = serde_json::json!(description);
    }

    let content =
        serde_json::to_string_pretty(&pkg).map_err(|e| LpmError::Registry(e.to_string()))?;

    std::fs::write(&pkg_json_path, format!("{content}\n"))?;

    // Pre-create .gitattributes so lpm.lockb is marked as binary from the start
    if let Err(e) = lpm_lockfile::ensure_gitattributes(project_dir) {
        tracing::warn!("failed to ensure .gitattributes: {e}");
    }

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "name": full_name,
            "version": version,
            "path": pkg_json_path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        output::success(&format!("Created {}", "package.json".bold()));
        println!("  {}", full_name.dimmed());
        println!();
    }

    Ok(())
}

/// Look up the logged-in user's lpm.dev profile name to pre-fill the owner
/// default. Falls back to the literal `"username"` on any failure (offline,
/// no token, expired session, profile not set on the account) — init must
/// not block on the network or fail for users who haven't logged in yet.
async fn resolve_owner_default(client: &RegistryClient) -> String {
    const FALLBACK: &str = "username";
    const TIMEOUT: Duration = Duration::from_secs(3);

    match tokio::time::timeout(TIMEOUT, client.whoami()).await {
        Ok(Ok(user)) => user
            .profile_username
            .unwrap_or_else(|| FALLBACK.to_string()),
        _ => FALLBACK.to_string(),
    }
}
