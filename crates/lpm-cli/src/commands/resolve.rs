use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_resolver::resolve_dependencies;
use owo_colors::OwoColorize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

pub async fn run(
    client: &RegistryClient,
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

    // Phase 35 Step 6 fix: use the injected client. Pre-fix this site
    // hardcoded `https://lpm.dev` and only honored `LPM_TOKEN`,
    // ignoring `--registry` and the stored session entirely. The
    // injected client carries both the user's `--registry` URL and
    // the shared `SessionManager`, so this respects every layer of
    // the Phase 35 auth model with zero local construction.
    let arc_client = Arc::new(client.clone_with_config());

    match resolve_dependencies(arc_client, deps).await {
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
