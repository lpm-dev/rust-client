use std::path::Path;

use lpm_registry::RegistryClient;

/// Run `lpm install` without emitting a second report into Doctor's stdout.
pub(super) async fn run_doctor_install(
    client: &RegistryClient,
    project_dir: &Path,
) -> crate::commands::install::QuietInstall {
    crate::commands::install::run_silent_for_audit_fix(client, project_dir).await
}
