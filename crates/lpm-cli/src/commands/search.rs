use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;

pub async fn run(
    client: &RegistryClient,
    query: &str,
    limit: u32,
    json_output: bool,
) -> Result<(), LpmError> {
    let results = client.search_packages(query, limit).await?;

    if json_output {
        let json = serde_json::to_string_pretty(&results)?;
        println!("{json}");
        return Ok(());
    }

    if results.packages.is_empty() {
        output::warn(&format!("No packages found for \"{query}\""));
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
        let owner = pkg.owner.as_deref().unwrap_or("?");
        let version = pkg.latest_version.as_deref().unwrap_or("?");
        let mode = pkg
            .distribution_mode
            .as_deref()
            .map(|m| output::mode_badge(m))
            .unwrap_or_default();

        println!(
            "  {}  {}  {mode}",
            format!("@lpm.dev/{owner}.{}", pkg.name).bold(),
            format!("v{version}").dimmed(),
        );

        if let Some(desc) = &pkg.description {
            if !desc.is_empty() {
                let short = if desc.len() > 80 {
                    format!("{}...", &desc[..77])
                } else {
                    desc.clone()
                };
                println!("    {}", short.dimmed());
            }
        }

        if let Some(downloads) = pkg.download_count {
            if downloads > 0 {
                println!("    {} downloads", downloads.to_string().dimmed());
            }
        }
        println!();
    }

    Ok(())
}
