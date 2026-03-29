use crate::output;
use lpm_common::LpmError;
use owo_colors::OwoColorize;
use std::path::Path;

/// Remove a source-delivered package (reverse of `lpm add`).
///
/// Removes files that were copied by `lpm add` and cleans up the target directory.
pub async fn run(
	project_dir: &Path,
	package: &str,
	json_output: bool,
) -> Result<(), LpmError> {
	// Strategy: check common target directories for the package's files
	// Since `add` copies source files, we need to find where they were put.
	// The most reliable way is to check if there's a skills directory for this package
	// (skills are always at .lpm/skills/<owner.name>/)

	let name = lpm_common::PackageName::parse(package)?;
	let short = name.short();

	let mut removed_paths = Vec::new();

	// Remove skills for this package
	let skills_dir = project_dir.join(".lpm").join("skills").join(&short);
	if skills_dir.exists() {
		std::fs::remove_dir_all(&skills_dir)?;
		removed_paths.push(format!(".lpm/skills/{short}/"));
	}

	// Remove editor integration for this package's skills (e.g. Cursor symlinks)
	crate::editor_skills::remove_editor_skills(project_dir, &short);

	// Check common add targets for files from this package
	// Look for a marker: package directory matching the package name
	let pkg_short_name = short.split('.').last().unwrap_or(&short);
	for candidate in [
		"components",
		"src/components",
		"lib",
		"src/lib",
		"Packages/LPMComponents/Sources",
		"Sources",
	] {
		let candidate_dir = project_dir.join(candidate).join(pkg_short_name);
		if candidate_dir.exists() && candidate_dir.is_dir() {
			std::fs::remove_dir_all(&candidate_dir)?;
			removed_paths.push(format!("{candidate}/{pkg_short_name}/"));
		}
	}

	if json_output {
		println!(
			"{}",
			serde_json::to_string_pretty(&serde_json::json!({
				"package": package,
				"removed": removed_paths,
			}))
			.unwrap()
		);
	} else if removed_paths.is_empty() {
		output::warn(&format!(
			"No files found for {} — it may not have been added, or was added to a custom path",
			package.bold()
		));
	} else {
		output::success(&format!("Removed {}", package.bold()));
		for path in &removed_paths {
			println!("  {}", path.dimmed());
		}
		println!();
	}

	Ok(())
}
