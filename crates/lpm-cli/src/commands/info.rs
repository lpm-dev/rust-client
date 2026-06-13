use crate::commands::registry_reads::{
    fetch_routed_package_metadata, normalize_package_version_input, prepare_routed_read_context,
};
use crate::install_ui;
use lpm_common::color::Painted;
use lpm_common::{LpmError, sanitize_for_terminal};
use lpm_registry::RegistryClient;
use std::path::Path;

pub async fn run(
    client: &RegistryClient,
    project_dir: &Path,
    package: &str,
    version: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let (package, version) = normalize_package_version_input("info", package, version)?;
    let context =
        prepare_routed_read_context(client, project_dir, &[package.to_string()], json_output)?;
    let (_package_ref, metadata) = fetch_routed_package_metadata(&context, package).await?;

    if json_output {
        let mut json = serde_json::to_value(&metadata)?;
        if let Some(obj) = json.as_object_mut() {
            obj.insert("success".to_string(), serde_json::Value::Bool(true));
        }
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("{}", sanitize_for_terminal(&metadata.name).bold());

    // Determine which version to show
    let version_key = version
        .map(|v| v.to_string())
        .or_else(|| metadata.latest_version_tag().map(|s| s.to_string()));

    if let Some(ref vk) = version_key
        && let Some(ver) = metadata.version(vk)
    {
        print_field("version", &ver.version);

        if let Some(eco) = &ver.ecosystem {
            print_field("ecosystem", eco);
        }

        if let Some(integrity) = ver.integrity_or_shasum() {
            print_field("integrity", &short_integrity(integrity.as_ref()));
        }

        if let Some(desc) = &metadata.description
            && !desc.is_empty()
        {
            print_field("description", desc);
        }

        if !ver.dependencies.is_empty() {
            println!();
            println!("{}", install_ui::section("dependencies"));
            print_name_value_rows(&ver.dependencies);
        }

        if !ver.peer_dependencies.is_empty() {
            println!();
            println!("{}", install_ui::section("peer dependencies"));
            print_name_value_rows(&ver.peer_dependencies);
        }
    }

    if let Some(mode) = &metadata.distribution_mode {
        print_field("distribution", mode);
    }

    if let Some(downloads) = metadata.downloads {
        print_field("downloads", &downloads.to_string());
    }

    // All versions
    let mut versions: Vec<&str> = metadata.version_list();
    versions.sort();
    if !versions.is_empty() {
        println!();
        println!(
            "{}",
            install_ui::section(&format!("versions ({})", versions.len()))
        );
        let latest = metadata.latest_version_tag().unwrap_or("");
        for v in &versions {
            let safe_version = sanitize_for_terminal(v);
            if *v == latest {
                println!(
                    "  {:<12} {}",
                    safe_version,
                    install_ui::status_ok("(latest)")
                );
            } else {
                println!("  {}", safe_version.dimmed());
            }
        }
    }

    if let Some(tag) = metadata.dist_tags.get("latest")
        && let Some(time) = metadata.time.get(tag.as_str())
    {
        println!();
        print_field("published", time);
    }

    println!();
    install_ui::done("Loaded package metadata");
    Ok(())
}

fn print_field(label: &str, value: &str) {
    let safe_value = sanitize_for_terminal(value);
    println!("  {} {safe_value}", format!("{label:<12}").dimmed());
}

fn print_name_value_rows(values: &std::collections::HashMap<String, String>) {
    let mut rows: Vec<_> = values
        .iter()
        .map(|(name, value)| (sanitize_for_terminal(name), sanitize_for_terminal(value)))
        .collect();
    rows.sort_by(|(left, _), (right, _)| left.cmp(right));
    let width = rows.iter().map(|(name, _)| name.len()).max().unwrap_or(0);
    for (name, value) in rows {
        println!("  {name:<width$}  {}", value.dimmed());
    }
}

fn short_integrity(integrity: &str) -> String {
    const MAX_CHARS: usize = 30;
    const TAIL_CHARS: usize = 6;

    if integrity.chars().count() <= MAX_CHARS {
        return integrity.to_string();
    }

    let head_chars = MAX_CHARS - TAIL_CHARS - 1;
    let mut short = String::with_capacity(MAX_CHARS);
    short.extend(integrity.chars().take(head_chars));
    short.push('…');
    let tail_start = integrity.chars().count().saturating_sub(TAIL_CHARS);
    short.extend(integrity.chars().skip(tail_start));
    short
}
