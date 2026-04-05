use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Initialize a new package.json for an LPM package.
pub async fn run(project_dir: &Path, yes: bool, json_output: bool) -> Result<(), LpmError> {
    let pkg_json_path = project_dir.join("package.json");
    if pkg_json_path.exists() {
        return Err(LpmError::Registry("package.json already exists".into()));
    }

    let dir_name = project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-package");

    let (owner, name, version, description) = if yes {
        (
            "owner".to_string(),
            dir_name.to_string(),
            "1.0.0".to_string(),
            String::new(),
        )
    } else {
        let owner: String = cliclack::input("Owner (your username or org)")
            .placeholder("neo")
            .interact()
            .map_err(|e| LpmError::Registry(e.to_string()))?;

        let name: String = cliclack::input("Package name")
            .default_input(dir_name)
            .placeholder(dir_name)
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
