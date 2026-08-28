use std::time::{Duration, Instant};

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

use crate::install_ui;

const HEALTH_DEADLINE: Duration = Duration::from_secs(5);

pub async fn run(
    client: &RegistryClient,
    registry_url: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let start = Instant::now();
    let health_result =
        tokio::time::timeout(HEALTH_DEADLINE, client.diagnostic_health_check_once())
            .await
            .unwrap_or_else(|_| {
                Err(LpmError::Network(format!(
                    "registry health check exceeded its {}-second deadline",
                    HEALTH_DEADLINE.as_secs()
                )))
            });
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let display_registry_url = install_ui::safe_url_origin(registry_url);

    match health_result {
        Ok(true) => {
            if json_output {
                let json = serde_json::json!({
                    "success": true,
                    "healthy": true,
                    "registry_url": display_registry_url,
                    "response_time_ms": elapsed_ms,
                });
                let output = serde_json::to_string_pretty(&json).map_err(LpmError::Json)?;
                println!("{output}");
            } else {
                print_health_table(&display_registry_url, true, elapsed_ms);
                install_ui::done("Registry is reachable");
            }
        }
        Ok(false) => {
            if !json_output {
                print_health_table(&display_registry_url, false, elapsed_ms);
                install_ui::warn_untrusted(&format!(
                    "Registry at {} is unreachable",
                    display_registry_url
                ));
            }
            return Err(LpmError::Network(format!(
                "registry at {display_registry_url} is unreachable"
            )));
        }
        Err(error) => {
            if !json_output {
                print_health_table(&display_registry_url, false, elapsed_ms);
                install_ui::warn_untrusted(&format!(
                    "Registry at {} is unreachable",
                    display_registry_url
                ));
            }
            return Err(error);
        }
    }

    Ok(())
}

fn print_health_table(registry_url: &str, healthy: bool, elapsed_ms: u64) {
    let status = if healthy {
        format!(
            "{} {}",
            install_ui::bullet(true),
            install_ui::status_ok("healthy")
        )
    } else {
        format!(
            "{} {}",
            install_ui::bullet(false),
            install_ui::red("unreachable")
        )
    };

    eprintln!(
        "  {:<8} {}",
        install_ui::dim("Registry"),
        install_ui::url(registry_url)
    );
    eprintln!("  {:<8} {}", install_ui::dim("Status"), status);
    eprintln!(
        "  {:<8} {}",
        install_ui::dim("Response"),
        install_ui::status_ok(&format!("{elapsed_ms} ms"))
    );
}
