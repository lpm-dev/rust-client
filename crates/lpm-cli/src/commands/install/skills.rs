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

/// The skills an install materializes besides its dependencies' files.
pub(super) struct ProjectSkills<'a> {
    pub(super) client: &'a RegistryClient,
    pub(super) project_dir: &'a Path,
    /// Direct LPM.dev dependencies whose package skills to fetch, by name
    /// and selected version.
    pub(super) dependencies: &'a [(&'a str, &'a str)],
    /// Every direct LPM.dev dependency, fetched or not: `lpm-sources.json`
    /// skills of these come with the dependency's version instead.
    pub(super) direct: &'a std::collections::BTreeSet<&'a str>,
    /// Fetch package skills: those of `dependencies` and those
    /// `lpm-sources.json` records that this checkout lacks.
    pub(super) package_skills: bool,
    /// Restore the managed agent skills `lpm-agent-skills.json` records
    /// that this checkout lacks.
    pub(super) managed_skills: bool,
    pub(super) json_output: bool,
}

/// Materializes a project's skills. What can't be materialized, including
/// an unreadable record, becomes a warning, returned and printed outside
/// JSON mode: skills never fail an install whose dependencies are linked.
pub(super) async fn install_project_skills(input: ProjectSkills<'_>) -> Vec<String> {
    let mut warnings = Vec::new();
    if input.package_skills {
        let added =
            missing_added_source_skills(input.project_dir, input.direct).unwrap_or_else(|error| {
                let warning = format!(
                    "package skills recorded in {} were not restored: {}",
                    crate::added_sources_state::FILENAME,
                    crate::commands::skills::warning_detail(&error)
                );
                if !input.json_output {
                    output::warn(&lpm_common::sanitize_terminal_inline(&warning));
                }
                warnings.push(warning);
                Vec::new()
            });
        let mut packages = input.dependencies.to_vec();
        packages.extend(
            added
                .iter()
                .map(|(name, version)| (name.as_str(), version.as_str())),
        );
        if !packages.is_empty() {
            warnings.extend(
                install_skills_for_packages(
                    input.client,
                    &packages,
                    input.project_dir,
                    input.json_output,
                )
                .await,
            );
        }
    }
    if input.managed_skills {
        warnings.extend(restore_managed_project_skills(input.project_dir, input.json_output).await);
    }
    warnings
}

/// The skills `lpm-sources.json` records for packages `lpm add` delivered,
/// other than `direct` dependencies, that aren't in `.lpm/skills/` at the
/// recorded version, so a fresh checkout gets them back.
fn missing_added_source_skills(
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
/// this checkout lacks. What can't be restored, including an unreadable
/// record, is returned as a warning, also printed outside JSON mode.
async fn restore_managed_project_skills(project_dir: &Path, json_output: bool) -> Vec<String> {
    if crate::commands::skills::project_skills_ready(project_dir) {
        return Vec::new();
    }
    let warnings = match crate::commands::skills::restore_project_skills(project_dir).await {
        Ok(summary) => {
            if !json_output && !summary.restored.is_empty() {
                output::info(&format!(
                    "Restored {} managed agent skill(s)",
                    summary.restored.len()
                ));
            }
            summary.warnings
        }
        Err(error) => vec![format!(
            "managed agent skills were not restored: {}",
            crate::commands::skills::warning_detail(&error)
        )],
    };
    if !json_output {
        for warning in &warnings {
            output::warn(&lpm_common::sanitize_terminal_inline(warning));
        }
    }
    warnings
}

/// Materializes the package-published skills of `packages`. A package whose
/// skills can't be fetched, aren't offered, or can't be written keeps its
/// installed skills and becomes a warning, returned and printed outside
/// JSON mode.
async fn install_skills_for_packages(
    client: &RegistryClient,
    packages: &[(&str, &str)],
    project_dir: &Path,
    json_output: bool,
) -> Vec<String> {
    let fetched = futures::future::join_all(packages.iter().map(|(package, version)| {
        let short_name = package.strip_prefix("@lpm.dev/").unwrap_or(package);
        async move {
            let skills = fetch_package_skills(client, short_name, version).await;
            (short_name, *version, skills)
        }
    }))
    .await;

    let mut total_installed = 0usize;
    let mut warnings = Vec::new();
    for (short_name, version, skills) in fetched {
        let label = format!("@lpm.dev/{short_name}@{version}");
        let installed = skills.and_then(|skills| {
            crate::commands::skills::package::materialize(
                project_dir,
                short_name,
                Some(version),
                &skills,
            )
            .map_err(|error| {
                format!(
                    "package skills for {label} could not be written: {}",
                    crate::commands::skills::warning_detail(&error)
                )
            })
        });
        match installed {
            Ok(result) => total_installed += result.installed,
            Err(warning) => warnings.push(warning),
        }
    }

    if !json_output {
        if total_installed > 0 || warnings.is_empty() {
            output::info(&format!(
                "Materialized {total_installed} package-published skill(s)"
            ));
        }
        for warning in &warnings {
            output::warn(&lpm_common::sanitize_terminal_inline(warning));
        }
    }
    warnings
}

async fn fetch_package_skills(
    client: &RegistryClient,
    short_name: &str,
    version: &str,
) -> Result<Vec<lpm_registry::Skill>, String> {
    let label = format!("@lpm.dev/{short_name}@{version}");
    let response = client
        .get_skills(short_name, Some(version))
        .await
        .map_err(|error| {
            format!(
                "package skills for {label} could not be fetched: {}; existing skills were kept",
                crate::commands::skills::warning_detail(&error)
            )
        })?;
    if let Some(reason) = crate::commands::skills::package::unavailable_reason(&response) {
        return Err(reason.message(&label));
    }
    crate::commands::skills::package::validate(&response.skills).map_err(|error| {
        format!(
            "package skills for {label} were refused: {}; existing skills were kept",
            crate::commands::skills::warning_detail(&error)
        )
    })?;
    Ok(response.skills)
}
