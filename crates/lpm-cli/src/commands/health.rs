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
            Ok(true) => install_ui::done("Registry is healthy"),
            Ok(false) => {
                install_ui::warn(&format!("Registry at {} is unreachable", registry_url));
                return Err(LpmError::Network(format!(
                    "registry at {registry_url} is unreachable"
                )));
            }
            Err(error) => {
                install_ui::warn(&format!("Registry at {} is unreachable", registry_url));
                return Err(error);
            }
        }
    }

    Ok(())
}
