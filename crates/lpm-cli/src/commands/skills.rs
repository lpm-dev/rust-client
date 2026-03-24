use crate::output;
use lpm_common::LpmError;
use lpm_registry::RegistryClient;
use owo_colors::OwoColorize;
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
				LpmError::Registry("specify a package: lpm-rs skills install <package>".into())
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
			output::info("No skills installed");
		}
		return Ok(());
	}

	let mut skills = Vec::new();
	for entry in std::fs::read_dir(&skills_dir)? {
		let entry = entry?;
		if entry.path().extension().map(|e| e == "md").unwrap_or(false) {
			let name = entry
				.path()
				.file_stem()
				.unwrap_or_default()
				.to_string_lossy()
				.to_string();
			skills.push(name);
		}
	}

	if json_output {
		println!("{}", serde_json::to_string_pretty(&skills).unwrap());
	} else if skills.is_empty() {
		output::info("No skills installed");
	} else {
		println!("  {} skill(s) installed:", skills.len().to_string().bold());
		for name in &skills {
			println!("    {name}");
		}
		println!();
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
		output::info(&format!("Fetching skills for {}", name.scoped().bold()));
	}

	let skills = client.get_skills(&name.short(), None).await?;

	if skills.skills.is_empty() {
		if !json_output {
			output::info("Package has no skills");
		}
		return Ok(());
	}

	// Create skills directory
	let skills_dir = project_dir
		.join(".lpm")
		.join("skills")
		.join(name.short());
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

		let path = skills_dir.join(format!("{}.md", skill.name));
		std::fs::write(&path, content)?;
		installed += 1;
	}

	if json_output {
		println!(
			"{}",
			serde_json::to_string_pretty(&serde_json::json!({
				"installed": installed,
				"directory": skills_dir.display().to_string(),
			}))
			.unwrap()
		);
	} else {
		output::success(&format!("Installed {} skill(s)", installed));
		println!("  {}", skills_dir.display().to_string().dimmed());
		println!();
	}

	Ok(())
}

fn validate_skills(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
	let skills_dir = project_dir.join(".lpm").join("skills");
	if !skills_dir.exists() {
		if !json_output {
			output::info("No .lpm/skills/ directory found");
		}
		return Ok(());
	}

	let mut errors = Vec::new();
	let mut valid = 0;
	let mut total_size: u64 = 0;

	for entry in std::fs::read_dir(&skills_dir)?.flatten() {
		if !entry.path().extension().map(|e| e == "md").unwrap_or(false) {
			continue;
		}

		let path = entry.path();
		let name = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
		let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
		total_size += size;

		if size > 15 * 1024 {
			errors.push(format!("{name}: exceeds 15KB limit ({size} bytes)"));
			continue;
		}

		let content = std::fs::read_to_string(&path).unwrap_or_default();
		if content.len() < 100 {
			errors.push(format!("{name}: content too short (need 100+ chars)"));
			continue;
		}

		// Check for frontmatter
		if !content.starts_with("---") {
			errors.push(format!("{name}: missing YAML frontmatter"));
			continue;
		}

		valid += 1;
	}

	if total_size > 100 * 1024 {
		errors.push(format!(
			"total skills size {total_size} bytes exceeds 100KB limit"
		));
	}

	if json_output {
		println!(
			"{}",
			serde_json::to_string_pretty(&serde_json::json!({
				"valid": valid,
				"errors": errors,
			}))
			.unwrap()
		);
	} else if errors.is_empty() {
		output::success(&format!("{valid} skill(s) valid"));
	} else {
		for err in &errors {
			output::warn(err);
		}
		if valid > 0 {
			output::info(&format!("{valid} skill(s) valid, {} error(s)", errors.len()));
		}
	}

	Ok(())
}

fn clean_skills(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
	let skills_dir = project_dir.join(".lpm").join("skills");
	if !skills_dir.exists() {
		if !json_output {
			output::info("No skills to clean");
		}
		return Ok(());
	}

	std::fs::remove_dir_all(&skills_dir)?;

	if json_output {
		println!("{}", serde_json::json!({"cleaned": true}));
	} else {
		output::success("Skills directory cleaned");
	}

	Ok(())
}
