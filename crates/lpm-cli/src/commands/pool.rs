use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;

/// Show pool revenue stats.
pub async fn run(client: &RegistryClient, json_output: bool) -> Result<(), LpmError> {
    let stats = client.get_pool_stats().await?;

    if json_output {
        let mut json =
            serde_json::to_value(&stats).map_err(|e| LpmError::Registry(e.to_string()))?;
        if let Some(obj) = json.as_object_mut() {
            obj.insert("success".to_string(), serde_json::Value::Bool(true));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json).map_err(|e| LpmError::Registry(e.to_string()))?
        );
    } else {
        println!();
        println!("  {}", "Pool Revenue Stats".bold());
        println!();

        if let Some(period) = &stats.billing_period {
            print_field("billing period", period);
        }
        if let Some(downloads) = stats.total_weighted_downloads {
            print_field("weighted downloads", &format_count(downloads));
        }
        if let Some(earnings) = stats.estimated_earnings_cents {
            print_field(
                "estimated earnings",
                &format!("${:.2}", earnings as f64 / 100.0),
            );
        }

        if !stats.packages.is_empty() {
            println!();
            println!("  packages ({}):", stats.packages.len());
            let width = stats
                .packages
                .iter()
                .map(|package| package.name.len())
                .max()
                .unwrap_or(0);
            for pkg in &stats.packages {
                let downloads = pkg.weighted_downloads.unwrap_or(0);
                println!(
                    "    {:<width$}   {}",
                    pkg.name,
                    format!("({} downloads)", format_count(downloads)).dimmed()
                );
            }
        }

        println!();
    }

    Ok(())
}

fn print_field(label: &str, value: &str) {
    println!("  {label:<20} {value}");
}

fn format_count(value: u64) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);
    let leading = digits.len() % 3;
    if leading != 0 {
        formatted.push_str(&digits[..leading]);
    }
    for chunk_start in (leading..digits.len()).step_by(3) {
        if !formatted.is_empty() {
            formatted.push(',');
        }
        formatted.push_str(&digits[chunk_start..chunk_start + 3]);
    }
    formatted
}
