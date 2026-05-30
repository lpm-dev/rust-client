use crate::install_ui;
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use std::path::Path;

/// Skills management: list, install from a package, validate, clean.
pub async fn run(
    client: &RegistryClient,
    action: &str,
    package: Option<&str>,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        "list" | "ls" => list_skills(project_dir, json_output),
        "install" => {
            let pkg = package.ok_or_else(|| {
                LpmError::Registry("specify a package: lpm skills install <package>".into())
            })?;
            install_skills(client, pkg, project_dir, json_output).await
        }
        "validate" => validate_skills(project_dir, json_output),
        "clean" => clean_skills(project_dir, json_output),
        _ => Err(LpmError::Registry(format!(
            "unknown skills action: {action}. Use: list, install, validate, clean"
        ))),
    }
}

fn list_skills(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let skills_dir = project_dir.join(".lpm").join("skills");
    if !skills_dir.exists() {
        if !json_output {
            install_ui::warn("No skills installed");
        }
        return Ok(());
    }

    // Walk subdirectories: .lpm/skills/{owner.package}/*.md
    let mut packages: Vec<(String, Vec<(String, u64)>)> = Vec::new();

    for pkg_entry in std::fs::read_dir(&skills_dir)?.flatten() {
        if !pkg_entry.path().is_dir() {
            continue;
        }

        let pkg_name = pkg_entry.file_name().to_string_lossy().to_string();
        let mut skills = Vec::new();

        for skill_entry in std::fs::read_dir(pkg_entry.path())?.flatten() {
            let path = skill_entry.path();
            if path.extension().is_some_and(|e| e == "md") {
                let name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let size = skill_entry.metadata().map_or(0, |m| m.len());
                skills.push((name, size));
            }
        }

        if !skills.is_empty() {
            skills.sort_by(|a, b| a.0.cmp(&b.0));
            packages.push((pkg_name, skills));
        }
    }

    packages.sort_by(|a, b| a.0.cmp(&b.0));

    if json_output {
        // JSON output grouped by package
        let mut map = serde_json::Map::new();
        map.insert("success".to_string(), serde_json::Value::Bool(true));
        for (pkg, skills) in &packages {
            let arr: Vec<serde_json::Value> = skills
                .iter()
                .map(|(name, size)| serde_json::json!({"name": name, "size": size}))
                .collect();
            map.insert(pkg.clone(), serde_json::Value::Array(arr));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap()
        );
    } else if packages.is_empty() {
        install_ui::warn("No skills installed");
    } else {
        let total: usize = packages.iter().map(|(_, s)| s.len()).sum();
        for (pkg_name, skills) in &packages {
            println!("{}", format!("@lpm.dev/{pkg_name}").cyan());
            let width = skills
                .iter()
                .map(|(name, _)| name.len() + ".md".len())
                .max()
                .unwrap_or(0);
            for (name, size) in skills {
                let file_name = format!("{name}.md");
                println!(
                    "  {file_name:<width$}  {}",
                    lpm_common::format_bytes(*size).dimmed()
                );
            }
            println!();
        }
        install_ui::done(&format!(
            "{total} {} installed across {} {}",
            plural(total, "skill", "skills"),
            packages.len(),
            plural(packages.len(), "package", "packages"),
        ));
    }

    Ok(())
}

async fn install_skills(
    client: &RegistryClient,
    package: &str,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let name = lpm_common::PackageName::parse(package)?;

    if !json_output {
        install_ui::phase(&format!("Fetching skills for {}", name.scoped().bold()));
    }

    let skills = client.get_skills(&name.short(), None).await?;

    if skills.skills.is_empty() {
        if !json_output {
            install_ui::warn("Package has no skills");
        }
        return Ok(());
    }

    // Create skills directory
    let skills_dir = project_dir.join(".lpm").join("skills").join(name.short());
    std::fs::create_dir_all(&skills_dir)?;

    let mut installed = 0;
    for skill in &skills.skills {
        let content = skill
            .raw_content
            .as_deref()
            .or(skill.content.as_deref())
            .unwrap_or("");

        if content.is_empty() {
            continue;
        }

        if !lpm_common::is_safe_skill_name(&skill.name) {
            tracing::warn!("skipping skill with unsafe name: {}", skill.name);
            continue;
        }

        let path = skills_dir.join(format!("{}.md", skill.name));
        std::fs::write(&path, content)?;
        installed += 1;
    }

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "installed": installed,
                "directory": skills_dir.display().to_string(),
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!(
            "Installed {installed} {}",
            plural(installed, "skill", "skills"),
        ));
        eprintln!("  {}", skills_dir.display().to_string().dimmed());
    }

    Ok(())
}

fn validate_skills(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let skills_dir = project_dir.join(".lpm").join("skills");
    if !skills_dir.exists() {
        if !json_output {
            install_ui::warn("No .lpm/skills/ directory found");
        }
        return Ok(());
    }

    let mut errors = Vec::new();
    let mut valid = 0;
    let mut total_size: u64 = 0;

    // Walk subdirectories: .lpm/skills/{owner.package}/*.md
    for pkg_entry in std::fs::read_dir(&skills_dir)?.flatten() {
        let pkg_path = pkg_entry.path();
        if !pkg_path.is_dir() {
            continue;
        }

        for skill_entry in std::fs::read_dir(&pkg_path).into_iter().flatten().flatten() {
            let path = skill_entry.path();
            if path.extension().is_none_or(|e| e != "md") {
                continue;
            }

            let pkg_name = pkg_path.file_name().unwrap_or_default().to_string_lossy();
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let display_name = format!("{pkg_name}/{name}");
            let size = skill_entry.metadata().map_or(0, |m| m.len());
            total_size += size;

            if size > 15 * 1024 {
                errors.push(format!("{display_name}: exceeds 15KB limit ({size} bytes)"));
                continue;
            }

            let content = std::fs::read_to_string(&path).unwrap_or_default();
            if content.len() < 100 {
                errors.push(format!(
                    "{display_name}: content too short (need 100+ chars)"
                ));
                continue;
            }

            // Check for frontmatter
            if !content.starts_with("---") {
                errors.push(format!("{display_name}: missing YAML frontmatter"));
                continue;
            }

            valid += 1;
        }
    }

    if total_size > 100 * 1024 {
        errors.push(format!(
            "total skills size {total_size} bytes exceeds 100KB limit"
        ));
    }

    if json_output {
        let quality_impact = if valid >= 3 {
            10
        } else if valid > 0 {
            7
        } else {
            0
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": errors.is_empty(),
                "valid": valid,
                "errors": errors,
                "quality_impact": quality_impact,
            }))
            .unwrap()
        );
        // a non-empty `errors` list must surface as a
        // non-zero exit code so CI gates fail closed. The structured
        // envelope above carries the per-skill error list; returning
        // `LpmError::ExitCode(1)` exits non-zero while routing past
        // the top-level `--json` envelope handler so we don't emit a
        // second, less-informative envelope on top of the rich one.
        if !errors.is_empty() {
            return Err(LpmError::ExitCode(1));
        }
        return Ok(());
    } else if errors.is_empty() {
        install_ui::done(&format!(
            "{valid} {} valid",
            plural(valid, "skill", "skills"),
        ));
        if valid > 0 {
            let impact = if valid >= 3 {
                "+7 pts (has-skills) +3 pts (comprehensive)"
            } else {
                "+7 pts (has-skills)"
            };
            install_ui::phase(&format!("Quality impact: {}", impact.green()));
        }
    } else {
        for err in &errors {
            install_ui::warn(err);
        }
        if valid > 0 {
            install_ui::phase(&format!(
                "{valid} {} valid, {} {}",
                plural(valid, "skill", "skills"),
                errors.len(),
                plural(errors.len(), "error", "errors"),
            ));
        }
    }

    // human-mode path. Per-skill warnings have already
    // been emitted above; return a concise summary error so the
    // top-level miette handler renders an "Error: …" footer AND the
    // process exits non-zero. Without this, CI gates that run
    // `lpm skills validate` silently passed on broken skill files.
    // Mirrors the contract of every other audit/lint-style command.
    if !errors.is_empty() {
        return Err(LpmError::Script(format!(
            "{} skill validation error(s)",
            errors.len()
        )));
    }

    Ok(())
}

fn clean_skills(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let skills_dir = project_dir.join(".lpm").join("skills");
    if !skills_dir.exists() {
        if !json_output {
            install_ui::warn("No skills to clean");
        }
        return Ok(());
    }

    // Count files before removing
    let file_count = count_files_recursive(&skills_dir);

    std::fs::remove_dir_all(&skills_dir)?;

    if json_output {
        println!(
            "{}",
            serde_json::json!({"success": true, "cleaned": true, "files_removed": file_count})
        );
    } else {
        install_ui::done(&format!(
            "Skills cleaned · removed {file_count} {}",
            plural(file_count, "file", "files"),
        ));
    }

    Ok(())
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn count_files_recursive(dir: &Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                count += count_files_recursive(&entry.path());
            } else {
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_skills_walks_subdirectories() {
        let dir = tempfile::tempdir().unwrap();
        let skills_dir = dir.path().join(".lpm").join("skills");
        let pkg_dir = skills_dir.join("owner.pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        // Valid skill with frontmatter and 100+ chars
        let content = format!(
            "---\nname: guide\ndescription: A helpful guide\n---\n{}",
            "x".repeat(100)
        );
        std::fs::write(pkg_dir.join("guide.md"), &content).unwrap();

        // Call validate_skills; it should find the skill in the subdirectory
        let result = validate_skills(dir.path(), true);
        assert!(result.is_ok());
        // The JSON output goes to stdout — we just verify no error
    }

    #[test]
    fn validate_skills_empty_dir_no_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_skills(dir.path(), true);
        assert!(result.is_ok());
    }
}
