use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;

/// Show pool revenue stats.
pub async fn run(client: &RegistryClient, json_output: bool) -> Result<(), LpmError> {
	let stats = client.get_pool_stats().await?;

	if json_output {
		let json = serde_json::to_string_pretty(&stats)
			.map_err(|e| LpmError::Registry(e.to_string()))?;
		println!("{json}");
	} else {
		println!();
		println!("  {}", "Pool Revenue Stats".bold());
		println!();

		if let Some(period) = &stats.billing_period {
			output::field("billing period", period);
		}
		if let Some(downloads) = stats.total_weighted_downloads {
			output::field("weighted downloads", &downloads.to_string());
		}
		if let Some(earnings) = stats.estimated_earnings_cents {
			output::field(
				"estimated earnings",
				&format!("${:.2}", earnings as f64 / 100.0),
			);
		}

		if !stats.packages.is_empty() {
			output::header(&format!("packages ({})", stats.packages.len()));
			for pkg in &stats.packages {
				let downloads = pkg.weighted_downloads.unwrap_or(0);
				println!(
					"    {} {}",
					pkg.name,
					format!("({downloads} downloads)").dimmed()
				);
			}
		}

		println!();
	}

	Ok(())
}
