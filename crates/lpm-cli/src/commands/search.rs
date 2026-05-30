use crate::commands::registry_reads::{prepare_routed_read_context, search_route_for_query};
use crate::install_ui;
use crate::output;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use std::path::Path;

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    query: &str,
    limit: u32,
    json_output: bool,
) -> Result<(), LpmError> {
    let context =
        prepare_routed_read_context(client, project_dir, &[query.to_string()], json_output)?;
    let route = search_route_for_query(&context.route_table, query);
    if !json_output {
        install_ui::phase(&format!("Searching lpm.dev for \"{query}\""));
    }
    let results = context
        .client
        .search_npm_packages_routed(query, limit, route)
        .await?;

    if json_output {
        let mut json = serde_json::to_value(&results)?;
        if let Some(obj) = json.as_object_mut() {
            obj.insert("success".to_string(), serde_json::Value::Bool(true));
            obj.insert(
                "count".to_string(),
                serde_json::json!(results.packages.len()),
            );
        }
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    if results.packages.is_empty() {
        install_ui::warn(&format!("No packages found for \"{query}\""));
        return Ok(());
    }

    println!();
    println!(
        "  {} package(s) for \"{}\":",
        results.packages.len().to_string().bold(),
        query.bold()
    );
    println!();

    for pkg in &results.packages {
        let version = pkg.latest_version.as_deref().unwrap_or("?");
        let mode = pkg
            .distribution_mode
            .as_deref()
            .map(output::mode_badge)
            .unwrap_or_default();
        let package_name = match pkg.owner.as_deref() {
            Some(owner) => format!("@lpm.dev/{owner}.{}", pkg.name),
            None => pkg.name.clone(),
        };

        println!(
            "  {}  {}  {mode}",
            package_name.bold(),
            format!("v{version}").dimmed(),
        );

        if let Some(desc) = &pkg.description
            && !desc.is_empty()
        {
            let short = if desc.len() > 80 {
                format!("{}...", &desc[..77])
            } else {
                desc.clone()
            };
            println!("    {}", short.dimmed());
        }

        if let Some(downloads) = pkg.download_count
            && downloads > 0
        {
            let dl = format_downloads(downloads);
            println!("    {}", format!("↓ {dl}").green());
        }
        println!();
    }

    install_ui::done(&format!(
        "Found {} {}",
        results.packages.len(),
        install_ui::packages_word(results.packages.len())
    ));

    Ok(())
}

fn format_downloads(count: u64) -> String {
    if count >= 1_000_000 {
        format!("{}M", count / 1_000_000)
    } else if count >= 1_000 {
        format!("{}K", count / 1_000)
    } else {
        count.to_string()
    }
}
