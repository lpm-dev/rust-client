use super::*;

pub(super) fn selected_package_skills(
    packages: &[InstallPackage],
) -> Result<Vec<(&str, &str)>, LpmError> {
    let mut selected = std::collections::BTreeMap::<&str, (&str, lpm_resolver::NpmVersion)>::new();
    for package in packages
        .iter()
        .filter(|package| package.is_lpm && package.is_direct)
    {
        let version =
            lpm_resolver::NpmVersion::parse(&package.version).map_err(LpmError::Registry)?;
        let entry = selected
            .entry(package.name.as_str())
            .or_insert_with(|| (package.version.as_str(), version.clone()));
        if (&version, package.version.as_str()) > (&entry.1, entry.0) {
            *entry = (&package.version, version);
        }
    }
    Ok(selected
        .into_iter()
        .map(|(name, (version, _))| (name, version))
        .collect())
}

/// The skills `lpm-sources.json` records for packages `lpm add` delivered,
/// other than `direct` dependencies, that aren't in `.lpm/skills/` at the
/// recorded version, so a fresh checkout gets them back.
pub(super) fn missing_added_source_skills(
    project_dir: &Path,
    direct: &std::collections::BTreeSet<&str>,
) -> Result<Vec<(String, String)>, LpmError> {
    Ok(
        crate::commands::skills::package::added_source_skills(project_dir, direct)?
            .into_iter()
            .filter(|(name, version)| {
                !crate::commands::skills::package::version_is_materialized(
                    project_dir,
                    name,
                    version,
                )
            })
            .collect(),
    )
}

/// Restores the managed agent skills `lpm-agent-skills.json` records that
/// this checkout lacks. What can't be restored is a warning.
pub(super) async fn restore_managed_project_skills(
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if crate::commands::skills::project_skills_ready(project_dir) {
        return Ok(());
    }
    let summary = crate::commands::skills::restore_project_skills(project_dir).await?;
    if !json_output {
        if !summary.restored.is_empty() {
            output::info(&format!(
                "Restored {} managed agent skill(s)",
                summary.restored.len()
            ));
        }
        for warning in &summary.warnings {
            output::warn(&lpm_common::sanitize_terminal_inline(warning));
        }
    } else {
        for warning in &summary.warnings {
            tracing::warn!("{warning}");
        }
    }
    Ok(())
}

pub(super) async fn install_skills_for_packages(
    client: &Arc<RegistryClient>,
    packages: &[(&str, &str)],
    project_dir: &Path,
    show_progress: bool,
) -> Result<(), LpmError> {
    let futures: Vec<_> = packages
        .iter()
        .map(|(package, version)| {
            let client = Arc::clone(client);
            let package = *package;
            let version = *version;
            async move {
                let short_name = package
                    .strip_prefix("@lpm.dev/")
                    .unwrap_or(package)
                    .to_string();
                let response = client.get_skills(&short_name, Some(version)).await?;
                crate::commands::skills::package::validate_response(&response)?;
                Ok::<_, LpmError>((short_name, version, response.skills))
            }
        })
        .collect();
    let fetched = futures::future::join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let mut total_installed = 0usize;
    for (short_name, version, skills) in fetched {
        let result = crate::commands::skills::package::materialize(
            project_dir,
            &short_name,
            Some(version),
            &skills,
        )?;
        total_installed += result.installed;
    }

    if show_progress {
        output::info(&format!(
            "Materialized {total_installed} package-published skill(s)"
        ));
    }
    Ok(())
}
