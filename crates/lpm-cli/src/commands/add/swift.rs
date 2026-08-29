use super::run_locked;
use crate::output;
use lpm_common::{LpmError, sanitize_terminal_inline};
use lpm_registry::{RegistryClient, VersionMetadata};
use std::collections::HashMap;
use std::path::Path;

#[derive(Default)]
pub(super) struct SwiftTraversal {
    resolved: HashMap<String, String>,
    warnings: Vec<String>,
}

impl SwiftTraversal {
    pub(super) fn record_resolution(
        &mut self,
        package: &str,
        version: &str,
    ) -> Result<bool, LpmError> {
        let Some(existing) = self.resolved.get(package) else {
            self.resolved
                .insert(package.to_string(), version.to_string());
            return Ok(true);
        };
        if existing == version {
            return Ok(false);
        }
        Err(LpmError::Registry(format!(
            "Swift source dependency '{}' resolved to incompatible versions '{}' and '{}'",
            sanitize_terminal_inline(package),
            sanitize_terminal_inline(existing),
            sanitize_terminal_inline(version)
        )))
    }

    fn already_satisfies(&self, package: &str, range: &str) -> Result<bool, LpmError> {
        let Some(version) = self.resolved.get(package) else {
            return Ok(false);
        };
        let requirement = lpm_semver::VersionReq::parse(range).map_err(|_| {
            LpmError::Registry(format!(
                "invalid Swift source dependency range '{}' for '{}'",
                sanitize_terminal_inline(range),
                sanitize_terminal_inline(package)
            ))
        })?;
        let resolved = lpm_semver::Version::parse(version).map_err(|_| {
            LpmError::Registry(format!(
                "invalid resolved Swift source dependency version '{}' for '{}'",
                sanitize_terminal_inline(version),
                sanitize_terminal_inline(package)
            ))
        })?;
        if requirement.matches(&resolved) {
            return Ok(true);
        }
        Err(LpmError::Registry(format!(
            "Swift source dependency '{}' requires '{}', but the source graph already selected '{}'",
            sanitize_terminal_inline(package),
            sanitize_terminal_inline(range),
            sanitize_terminal_inline(version)
        )))
    }

    pub(super) fn push_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub(super) fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

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
    no_engine_strict: bool,
    pm: &str,
    traversal: &mut SwiftTraversal,
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
        if traversal.already_satisfies(dep_name, dep_range)? {
            continue;
        }
        if !json_output {
            output::info(&format!(
                "  Adding dependency: {}@{}",
                sanitize_terminal_inline(dep_name),
                sanitize_terminal_inline(dep_range)
            ));
        }
        let dependency_spec = format!("{dep_name}@{dep_range}");
        Box::pin(run_locked(
            client,
            project_dir,
            &dependency_spec,
            None,
            yes,
            json_output,
            force,
            dry_run,
            no_install_deps,
            no_skills,
            no_editor_setup,
            no_engine_strict,
            pm,
            None,
            None,
            traversal,
            false,
        ))
        .await?;
    }

    Ok(())
}
