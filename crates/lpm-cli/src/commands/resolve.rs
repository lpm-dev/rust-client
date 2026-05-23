use crate::commands::registry_reads::prepare_routed_read_context;
use crate::output;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use lpm_resolver::resolve_dependencies_routed;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    packages: &[String],
    json_output: bool,
) -> Result<(), LpmError> {
    // Parse packages into deps map: "name@range" or "name" (defaults to *)
    let mut deps: HashMap<String, String> = HashMap::new();
    for pkg_str in packages {
        let (name, range) = if let Some(at_pos) = pkg_str.rfind('@') {
            // Careful: @lpm.dev/owner.pkg@1.0.0 — the last @ is the version separator
            if at_pos > 0 {
                (&pkg_str[..at_pos], &pkg_str[at_pos + 1..])
            } else {
                (pkg_str.as_str(), "*")
            }
        } else {
            (pkg_str.as_str(), "*")
        };
        deps.insert(name.to_string(), range.to_string());
    }

    if deps.is_empty() {
        return Err(LpmError::Registry("no packages specified".into()));
    }

    let start = Instant::now();

    output::info(&format!(
        "Resolving {} package(s)...",
        deps.len().to_string().bold()
    ));

    let top_level_specs: Vec<String> = deps.keys().cloned().collect();
    let context = prepare_routed_read_context(client, project_dir, &top_level_specs, json_output)?;
    let arc_client = Arc::new(context.client.clone_with_config());

    match resolve_dependencies_routed(arc_client, deps, context.route_table).await {
        Ok(result) => {
            let elapsed = start.elapsed();
            let resolved = &result.packages;

            if json_output {
                let json_pkgs: Vec<serde_json::Value> = resolved
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "package": r.package.to_string(),
                            "version": r.version.to_string(),
                        })
                    })
                    .collect();
                let json = serde_json::json!({
                    "success": true,
                    "packages": json_pkgs,
                    "count": resolved.len(),
                    "elapsed_secs": elapsed.as_secs_f64(),
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
                return Ok(());
            }

            output::success(&format!(
                "Resolved {} package(s) in {:.1}s",
                resolved.len().to_string().bold(),
                elapsed.as_secs_f64()
            ));
            println!();

            for r in resolved {
                let kind = if r.package.is_lpm() {
                    "lpm".cyan().to_string()
                } else {
                    "npm".dimmed().to_string()
                };
                println!(
                    "  {} {} {}",
                    r.package.to_string().bold(),
                    format!("v{}", r.version).dimmed(),
                    kind
                );
            }
            println!();

            Ok(())
        }
        Err(e) => Err(LpmError::Registry(format!("resolution failed: {e}"))),
    }
}
