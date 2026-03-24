use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;

pub async fn run(client: &RegistryClient) -> Result<(), LpmError> {
    let healthy = client.health_check().await?;

    if healthy {
        output::success("Registry is healthy");
    } else {
        eprintln!("Registry is unreachable");
        std::process::exit(1);
    }

    Ok(())
}
