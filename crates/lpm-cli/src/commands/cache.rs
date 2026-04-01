use crate::output;
use lpm_common::LpmError;
use lpm_store::PackageStore;
use owo_colors::OwoColorize;

/// Manage the global package cache at ~/.lpm/store/.
pub async fn run(action: &str, json_output: bool) -> Result<(), LpmError> {
    let store = PackageStore::default_location()?;

    match action {
        "list" | "ls" => {
            let packages = store.list_packages()?;
            if json_output {
                let entries: Vec<_> = packages
                    .iter()
                    .map(|(name, ver)| serde_json::json!({"name": name, "version": ver}))
                    .collect();
                let json = serde_json::json!({
                    "success": true,
                    "packages": entries,
                    "count": packages.len(),
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else if packages.is_empty() {
                output::info("Cache is empty");
            } else {
                println!("  {} packages in cache:", packages.len().to_string().bold());
                for (name, version) in &packages {
                    println!("    {}@{}", name, version.dimmed());
                }
                println!();
            }
        }
        "clean" | "clear" => {
            let packages = store.list_packages()?;
            let count = packages.len();

            if count == 0 {
                if json_output {
                    let json = serde_json::json!({
                        "success": true,
                        "cleared": 0,
                    });
                    println!("{}", serde_json::to_string_pretty(&json).unwrap());
                } else {
                    output::info("Cache is already empty");
                }
                return Ok(());
            }

            // Remove the entire store directory
            let store_dir = store.root().join("v1");
            if store_dir.exists() {
                std::fs::remove_dir_all(&store_dir)?;
            }

            if json_output {
                let json = serde_json::json!({
                    "success": true,
                    "cleared": count,
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else {
                output::success(&format!("Cleared {} packages from cache", count));
            }
        }
        "path" => {
            let path = store.root().display().to_string();
            if json_output {
                let json = serde_json::json!({
                    "success": true,
                    "path": path,
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else {
                println!("{path}");
            }
        }
        _ => {
            return Err(LpmError::Registry(format!(
                "unknown cache action: {action}. Use: list, clean, path"
            )));
        }
    }

    Ok(())
}
