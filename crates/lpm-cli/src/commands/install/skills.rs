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

    ensure_skills_gitignore(project_dir);
    if show_progress {
        output::info(&format!(
            "Materialized {total_installed} package-published skill(s)"
        ));
    }
    Ok(())
}
