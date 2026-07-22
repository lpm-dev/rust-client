use crate::install_ui;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::time::Instant;

pub async fn run(
    client: &RegistryClient,
    registry_url: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let start = Instant::now();
    let health_result = client.health_check().await;
    let elapsed_ms = start.elapsed().as_millis() as u64;

    if json_output {
        let healthy = health_result?;
        let json = serde_json::json!({
            "success": true,
            "healthy": healthy,
            "registry_url": registry_url,
            "response_time_ms": elapsed_ms,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        match health_result {
            Ok(true) => {
                print_health_table(registry_url, true, elapsed_ms);
                install_ui::done("Registry is reachable");
            }
            Ok(false) => {
                print_health_table(registry_url, false, elapsed_ms);
                install_ui::warn_untrusted(&format!("Registry at {} is unreachable", registry_url));
                return Err(LpmError::Network(format!(
                    "registry at {registry_url} is unreachable"
                )));
            }
            Err(error) => {
                print_health_table(registry_url, false, elapsed_ms);
                install_ui::warn_untrusted(&format!("Registry at {} is unreachable", registry_url));
                return Err(error);
            }
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
