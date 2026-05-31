use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;

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

    println!("{}", install_ui::cyan(&report.name));

    if let Some(score) = report.score {
        let max = report.max_score.unwrap_or(100);
        let tier = report.tier.as_deref().unwrap_or("—");
        print_field("score", &score_colored(score, max));
        print_field("tier", &tier_colored(tier));
    }

    if let Some(eco) = &report.ecosystem {
        print_field("ecosystem", eco);
    }

    if !report.checks.is_empty() {
        println!();
        println!("{}", install_ui::section("checks"));

        let label_width = report
            .checks
            .iter()
            .map(|check| check.label.as_deref().unwrap_or(&check.id).len())
            .max()
            .unwrap_or(0);

        for check in &report.checks {
            let passed = check.passed.unwrap_or(false);
            let icon = if passed {
                install_ui::green("✓")
            } else {
                install_ui::red("✗")
            };
            let label = check.label.as_deref().unwrap_or(&check.id);
            let points = format_points(passed, check.points.unwrap_or(0), check.max_points);

            let points = if passed {
                install_ui::green(&points)
            } else {
                install_ui::dim(&points)
            };
            println!("  {icon} {label:<label_width$}  {points}");

            if let Some(detail) = &check.detail
                && !detail.is_empty()
                && !passed
            {
                println!("    {}", install_ui::dim(detail));
            }
        }
    }

    println!();
    install_ui::done("Quality report ready");
    Ok(())
}

fn print_field(label: &str, value: &str) {
    println!("  {} {value}", install_ui::dim(&format!("{label:<10}")));
}

fn score_colored(score: u32, max: u32) -> String {
    install_ui::status_ok(&format!("{score}/{max}"))
}

fn tier_colored(tier: &str) -> String {
    install_ui::status_ok(tier)
}

fn format_points(passed: bool, points: u32, max_points: Option<u32>) -> String {
    if passed {
        return format!("+{points}");
    }
    match max_points {
        Some(max) if max > 0 => format!("{points}/{max}"),
        _ => points.to_string(),
    }
}
