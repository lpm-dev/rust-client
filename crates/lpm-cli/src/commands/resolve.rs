mod graph;
#[cfg(test)]
mod tests;

use crate::commands::registry_reads::{
    normalize_package_version_input, prepare_routed_read_context,
};
use crate::install_ui;
use graph::{Graph, RenderLimits};
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use lpm_resolver::{CompiledPeerRules, check_unmet_peers, resolve_dependencies_routed};
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
    let mut deps = HashMap::with_capacity(packages.len());
    let mut requested_roots = Vec::with_capacity(packages.len());
    let mut top_level_specs = Vec::with_capacity(packages.len());
    for input in packages {
        let (name, range) = normalize_package_version_input("resolve", input, None)?;
        let range = range.unwrap_or("*");
        if let Some(previous) = deps.get(name) {
            if previous != range {
                return Err(LpmError::Registry(format!(
                    "conflicting requests for {name}: '{previous}' and '{range}'; specify one range per local package name"
                )));
            }
            continue;
        }
        requested_roots.push(name.to_owned());
        top_level_specs.push(
            lpm_resolver::ranges::parse_npm_alias(range)
                .map_or_else(|| name.to_owned(), |alias| alias.target),
        );
        deps.insert(name.to_owned(), range.to_owned());
    }
    if deps.is_empty() {
        return Err(LpmError::Registry("no packages specified".into()));
    }
    let start = Instant::now();
    if !json_output {
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Resolving {} {}",
            install_ui::bold(&deps.len().to_string()),
            install_ui::packages_word(deps.len())
        ));
    }
    let context = prepare_routed_read_context(client, project_dir, &top_level_specs, json_output)?;
    let result = resolve_dependencies_routed(
        Arc::new(context.client.clone_with_config()),
        deps,
        context.route_table,
    )
    .await
    .map_err(crate::resolver_error::resolver_error_to_lpm)?;
    let graph = Graph::new(&result.packages)?;
    let roots = graph.roots(&requested_roots, &result.root_resolutions)?;
    let warnings = check_unmet_peers(
        &result.packages,
        &result.cache,
        &CompiledPeerRules::default(),
    );
    let elapsed = start.elapsed();
    if json_output {
        let json = serde_json::json!({
            "success":true,
            "packages":graph.packages_json(),
            "roots":roots.iter().map(|(name,target)|serde_json::json!({"name":name,"target":target.get()})).collect::<Vec<_>>(),
            "ambient_peer_installs":result.ambient_peer_installs,
            "peer_issues":crate::commands::install::peer_issues_json_value(&warnings,&result.peer_conflicts),
            "count":result.packages.len(),
            "elapsed_secs":elapsed.as_secs_f64(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json)
                .map_err(|error| LpmError::Registry(error.to_string()))?
        );
    } else {
        println!();
        graph.render(
            &roots,
            &mut std::io::stdout().lock(),
            RenderLimits::default(),
        )?;
        println!();
        for warning in &warnings {
            install_ui::warn_untrusted(&warning.to_string());
        }
        for conflict in &result.peer_conflicts {
            for (consumer, range) in &conflict.unsatisfied_consumers {
                install_ui::warn_untrusted(&format!(
                    "peer conflict: {consumer} requires {} ({range}); selected {}",
                    conflict.canonical, conflict.chosen_version
                ));
            }
        }
        install_ui::done_line(crate::install_ui::terminal_line!(
            "Resolved {} {} in {}",
            install_ui::bold(&result.packages.len().to_string()),
            install_ui::packages_word(result.packages.len()),
            install_ui::green(&install_ui::format_duration(elapsed))
        ));
    }
    Ok(())
}
