use super::*;

/// Auto-install agent skills for direct LPM packages.
///
/// For each direct LPM dependency, fetches its skills from the registry and
/// writes them to `.lpm/skills/{owner.package}/`. Package-published skills
/// remain package-owned and are never linked into agent target directories.
pub(super) async fn install_skills_for_packages(
    client: &Arc<RegistryClient>,
    packages: &[(String, String)],
    project_dir: &Path,
    show_progress: bool,
    setup_editor_references: bool,
) {
    // Fetch all package skills in parallel
    let futures: Vec<_> = packages
        .iter()
        .map(|(pkg_name, version)| {
            let client = client.clone();
            let pkg = pkg_name.clone();
            let version = version.clone();
            async move {
                let short_name = pkg.strip_prefix("@lpm.dev/").unwrap_or(&pkg).to_string();
                let result = client.get_skills(&short_name, Some(&version)).await;
                (short_name, result)
            }
        })
        .collect();

    let results = futures::future::join_all(futures).await;

    let mut total_installed = 0;

    for (short_name, result) in results {
        match result {
            Ok(response) if !response.skills.is_empty() => {
                let skills_dir = project_dir.join(".lpm").join("skills").join(&short_name);
                let _ = std::fs::create_dir_all(&skills_dir);

                for skill in &response.skills {
                    if !lpm_common::is_safe_skill_name(&skill.name) {
                        tracing::warn!("skipping skill with unsafe name: {}", skill.name);
                        continue;
                    }

                    let content = skill
                        .raw_content
                        .as_deref()
                        .or(skill.content.as_deref())
                        .unwrap_or("");
                    if !content.is_empty() {
                        let path = skills_dir.join(format!("{}.md", skill.name));
                        let _ = std::fs::write(&path, content);
                        total_installed += 1;
                    }
                }
            }
            _ => {} // No skills or API error — skip silently
        }
    }

    if total_installed > 0 {
        if show_progress {
            output::info(&format!(
                "Installed {total_installed} package-published skill(s)"
            ));
        }

        // Ensure .gitignore includes .lpm/skills/
        ensure_skills_gitignore(project_dir);

        if setup_editor_references {
            let integrations = crate::editor_skills::auto_integrate_skills(project_dir);
            if show_progress {
                for message in integrations {
                    output::info(&message);
                }
            }
        }
    }
}
