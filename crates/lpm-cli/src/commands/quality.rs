use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;

pub async fn run(
    client: &RegistryClient,
    package: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let report = client.get_quality(package).await?;

    if json_output {
        let mut json = serde_json::to_value(&report)?;
        if let Some(obj) = json.as_object_mut() {
            obj.insert("success".to_string(), serde_json::Value::Bool(true));
        }
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!();
    println!("  {}", report.name.bold());
    println!();

    if let Some(score) = report.score {
        let max = report.max_score.unwrap_or(100);
        let tier = report.tier.as_deref().unwrap_or("—");
        output::field("score", &output::score_colored(score, max));
        output::field("tier", &output::tier_colored(tier));
    }

    if let Some(eco) = &report.ecosystem {
        output::field("ecosystem", eco);
    }

    if !report.checks.is_empty() {
        // Group by category
        let mut categories: std::collections::BTreeMap<String, Vec<&lpm_registry::QualityCheck>> =
            std::collections::BTreeMap::new();
        for check in &report.checks {
            let cat = check.category.as_deref().unwrap_or("other").to_string();
            categories.entry(cat).or_default().push(check);
        }

        for (category, checks) in &categories {
            output::header(category);
            for check in checks {
                let passed = check.passed.unwrap_or(false);
                let icon = if passed {
                    "+".green().to_string()
                } else {
                    "-".red().to_string()
                };
                let label = check.label.as_deref().unwrap_or(&check.id);
                let points = check.points.unwrap_or(0);
                let max = check.max_points.unwrap_or(0);

                println!(
                    "    [{icon}] {label}  {}",
                    format!("({points}/{max})").dimmed()
                );

                if let Some(detail) = &check.detail {
                    if !detail.is_empty() && !passed {
                        println!("        {}", detail.dimmed());
                    }
                }
            }
        }
    }

    println!();
    Ok(())
}
