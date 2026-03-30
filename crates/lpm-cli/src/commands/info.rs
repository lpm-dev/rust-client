use crate::output;
use lpm_common::{LpmError, PackageName};
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;

pub async fn run(
    client: &RegistryClient,
    package: &str,
    version: Option<&str>,
    json_output: bool,
) -> Result<(), LpmError> {
    let name = PackageName::parse(package)?;
    let metadata = client.get_package_metadata(&name).await?;

    if json_output {
        let mut json = serde_json::to_value(&metadata)?;
        if let Some(obj) = json.as_object_mut() {
            obj.insert("success".to_string(), serde_json::Value::Bool(true));
        }
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // Package name header
    println!();
    println!("  {}", metadata.name.bold());

    if let Some(desc) = &metadata.description {
        if !desc.is_empty() {
            println!("  {}", desc.dimmed());
        }
    }
    println!();

    // Determine which version to show
    let version_key = version
        .map(|v| v.to_string())
        .or_else(|| metadata.latest_version_tag().map(|s| s.to_string()));

    if let Some(ref vk) = version_key {
        if let Some(ver) = metadata.version(vk) {
            output::field("version", &ver.version);

            if let Some(eco) = &ver.ecosystem {
                output::field("ecosystem", eco);
            }

            if let Some(integrity) = ver.integrity() {
                let short = if integrity.len() > 30 {
                    format!("{}...", &integrity[..30])
                } else {
                    integrity.to_string()
                };
                output::field("integrity", &short);
            }

            if !ver.dependencies.is_empty() {
                output::header(&format!("dependencies ({})", ver.dependencies.len()));
                for (dep, range) in &ver.dependencies {
                    println!("    {} {}", dep, range.dimmed());
                }
            }

            if !ver.peer_dependencies.is_empty() {
                output::header(&format!("peer dependencies ({})", ver.peer_dependencies.len()));
                for (dep, range) in &ver.peer_dependencies {
                    println!("    {} {}", dep, range.dimmed());
                }
            }
        }
    }

    if let Some(mode) = &metadata.distribution_mode {
        output::field("distribution", &output::mode_badge(mode));
    }

    if let Some(downloads) = metadata.downloads {
        output::field("downloads", &format!("{downloads}"));
    }

    // All versions
    let mut versions: Vec<&str> = metadata.version_list();
    versions.sort();
    if !versions.is_empty() {
        output::header(&format!("versions ({})", versions.len()));
        let latest = metadata.latest_version_tag().unwrap_or("");
        for v in &versions {
            if *v == latest {
                println!("    {} {}", v, "(latest)".green());
            } else {
                println!("    {}", v.dimmed());
            }
        }
    }

    if let Some(tag) = metadata.dist_tags.get("latest") {
        if let Some(time) = metadata.time.get(tag.as_str()) {
            println!();
            output::field("published", time);
        }
    }

    println!();
    Ok(())
}
