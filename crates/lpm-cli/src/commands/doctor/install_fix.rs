use std::path::Path;

use lpm_common::LpmError;
use lpm_registry::RegistryClient;

/// Run `lpm install` without emitting a second report into Doctor's stdout.
pub(super) async fn run_doctor_install(
    client: &RegistryClient,
    project_dir: &Path,
) -> Result<(), LpmError> {
    crate::commands::install::run_silent_for_audit_fix(client, project_dir).await
}
