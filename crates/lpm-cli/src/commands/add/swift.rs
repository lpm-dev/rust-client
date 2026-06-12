use super::run;
use crate::output;
use lpm_common::LpmError;
use lpm_registry::{RegistryClient, VersionMetadata};
use std::path::Path;

/// For Swift packages: recursively install LPM dependencies.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_swift_lpm_deps(
    client: &RegistryClient,
    project_dir: &Path,
    ver_meta: &VersionMetadata,
    yes: bool,
    json_output: bool,
    force: bool,
    dry_run: bool,
    no_install_deps: bool,
    no_skills: bool,
    no_editor_setup: bool,
    pm: &str,
) -> Result<(), LpmError> {
    // Check versionMeta for swift manifest dependencies
    // These are in the version's metadata, not in lpm.config.json
    let deps = &ver_meta.dependencies;
    if deps.is_empty() {
        return Ok(());
    }

    // Filter to LPM deps only
    let lpm_deps: Vec<(&String, &String)> = deps
        .iter()
        .filter(|(name, _)| name.starts_with("@lpm.dev/"))
        .collect();

    if lpm_deps.is_empty() {
        return Ok(());
    }

    if !json_output {
        output::info(&format!(
            "This package has {} LPM dependencies -- installing recursively",
            lpm_deps.len()
        ));
    }

    for (dep_name, dep_range) in &lpm_deps {
        if !json_output {
            output::info(&format!("  Adding dependency: {dep_name}@{dep_range}"));
        }
        // Recursive add (source delivery for recursive deps)
        Box::pin(run(
            client,
            project_dir,
            dep_name,
            None,
            yes,
            json_output,
            force,
            dry_run,
            no_install_deps,
            no_skills,
            no_editor_setup,
            pm,
            None,
            None,
        ))
        .await?;
    }

    Ok(())
}
