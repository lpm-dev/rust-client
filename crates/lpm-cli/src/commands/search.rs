use crate::commands::registry_reads::{prepare_routed_read_context, search_route_for_query};
use crate::install_ui;
use lpm_common::{LpmError, sanitize_for_terminal};
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
        let registry_label = search_registry_label(&context.client, &route);
        let query_safe = sanitize_for_terminal(query);
        install_ui::phase_line(crate::install_ui::terminal_line!(
            "Searching {} for \"{}\"",
            registry_label,
            install_ui::cyan(&query_safe)
        ));
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
        let query_safe = sanitize_for_terminal(query);
        install_ui::warn_untrusted(&format!("No packages found for \"{query_safe}\""));
        return Ok(());
    }

    println!();

    for pkg in &results.packages {
        let version = pkg.latest_version.as_deref().unwrap_or("?");
        let package_name = match pkg.owner.as_deref() {
            Some(owner) => format!("@lpm.dev/{owner}.{}", pkg.name),
            None => pkg.name.clone(),
        };

        let package_name_safe = sanitize_for_terminal(&package_name);
        println!("  {}", install_ui::cyan(&package_name_safe));

        if let Some(desc) = &pkg.description
            && !desc.is_empty()
        {
            let safe_desc = sanitize_for_terminal(desc);
            let short = truncate_description(&safe_desc, 80);
            println!("    {}", install_ui::dim(&short));
        }

        println!(
            "    {}",
            format_search_metadata(version, pkg.quality_score, pkg.ecosystem.as_deref())
        );
        println!();
    }

    install_ui::done_untrusted(&format!(
        "Found {} {}",
        results.packages.len(),
        install_ui::packages_word(results.packages.len())
    ));

    Ok(())
}

fn search_registry_label(client: &RegistryClient, route: &lpm_registry::UpstreamRoute) -> String {
    match route {
        lpm_registry::UpstreamRoute::LpmWorker => "lpm.dev".to_string(),
        lpm_registry::UpstreamRoute::NpmDirect => {
            install_ui::short_registry_host(client.npm_registry_url())
        }
        lpm_registry::UpstreamRoute::Custom { target, .. } => {
            install_ui::short_registry_host(target.base_url.as_ref())
        }
    }
}

fn truncate_description(description: &str, max_chars: usize) -> String {
    if description.chars().count() <= max_chars {
        return description.to_string();
    }

    let keep = max_chars.saturating_sub(3);
    let mut truncated = String::with_capacity(max_chars);
    truncated.extend(description.chars().take(keep));
    truncated.push_str("...");
    truncated
}

fn format_search_metadata(
    version: &str,
    quality_score: Option<u32>,
    ecosystem: Option<&str>,
) -> String {
    let mut parts = Vec::with_capacity(3);
    let safe_version = sanitize_for_terminal(version);
    parts.push(format!("latest {}", install_ui::yellow(&safe_version)));
    if let Some(score) = quality_score {
        let score_text = score.to_string();
        let colored = if score >= 80 {
            install_ui::status_ok(&score_text)
        } else {
            install_ui::yellow(&score_text)
        };
        parts.push(format!("quality {colored}"));
    }
    if let Some(ecosystem) = ecosystem
        && !ecosystem.is_empty()
    {
        let safe_ecosystem = sanitize_for_terminal(ecosystem);
        parts.push(format!("ecosystem {safe_ecosystem}"));
    }

    if parts.len() == 1 {
        parts.remove(0)
    } else {
        parts.join(&format!(" {} ", install_ui::dim("·")))
    }
}

#[cfg(test)]
mod tests {
    use super::{format_search_metadata, search_registry_label, truncate_description};
    use lpm_registry::RegistryClient;

    #[test]
    fn search_metadata_includes_latest_quality_and_ecosystem() {
        lpm_common::color::set_enabled(false);

        assert_eq!(
            format_search_metadata("1.2.3", Some(91), Some("js")),
            "latest 1.2.3 · quality 91 · ecosystem js"
        );
    }

    #[test]
    fn search_description_truncation_preserves_char_boundaries() {
        assert_eq!(
            truncate_description("é".repeat(81).as_str(), 80)
                .chars()
                .count(),
            80
        );
    }

    #[test]
    fn search_registry_label_names_default_npm_registry_for_direct_route() {
        let client = RegistryClient::new();

        assert_eq!(
            search_registry_label(&client, &lpm_registry::UpstreamRoute::NpmDirect),
            "npmjs.org"
        );
    }
}
