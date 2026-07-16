use super::*;

pub(super) async fn install_skills_for_packages(
    client: &Arc<RegistryClient>,
    packages: &[(String, String)],
    project_dir: &Path,
    show_progress: bool,
) -> Result<(), LpmError> {
    let futures: Vec<_> = packages
        .iter()
        .map(|(package, version)| {
            let client = Arc::clone(client);
            let package = package.clone();
            let version = version.clone();
            async move {
                let short_name = package
                    .strip_prefix("@lpm.dev/")
                    .unwrap_or(&package)
                    .to_string();
                let response = client.get_skills(&short_name, Some(&version)).await?;
                crate::commands::skills::package::validate(&response.skills)?;
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
            Some(&version),
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
