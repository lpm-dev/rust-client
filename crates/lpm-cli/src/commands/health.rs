use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use std::time::Instant;

pub async fn run(
    client: &RegistryClient,
    registry_url: &str,
    json_output: bool,
) -> Result<(), LpmError> {
    let start = Instant::now();
    let healthy = client.health_check().await?;
    let elapsed_ms = start.elapsed().as_millis() as u64;

    if json_output {
        let json = serde_json::json!({
            "success": true,
            "healthy": healthy,
            "registry_url": registry_url,
            "response_time_ms": elapsed_ms,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else if healthy {
        output::success("Registry is healthy");
    } else {
        output::warn(&format!("Registry at {} is unreachable", registry_url));
    }

    if !healthy {
        return Err(LpmError::Network(format!(
            "registry at {registry_url} is unreachable"
        )));
    }

    Ok(())
}
