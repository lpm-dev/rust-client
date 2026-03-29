//! Auto-integration of LPM Agent Skills with AI code editors.
//!
//! Detects Claude Code, Cursor, Windsurf, GitHub Copilot, Augment, and Cline.
//! Symlinks or appends skill references into editor config files.

use std::path::{Path, PathBuf};

/// Supported AI code editors.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AiEditor {
	ClaudeCode,    // CLAUDE.md
	Cursor,        // .cursor/rules/ directory
	CursorRules,   // .cursorrules file
	Windsurf,      // .windsurfrules
	GitHubCopilot, // .github/copilot-instructions.md
	Augment,       // .augment/instructions.md
	Cline,         // .clinerules
}

impl AiEditor {
	pub fn name(&self) -> &str {
		match self {
			Self::ClaudeCode => "Claude Code",
			Self::Cursor => "Cursor",
			Self::CursorRules => "Cursor",
			Self::Windsurf => "Windsurf",
			Self::GitHubCopilot => "GitHub Copilot",
			Self::Augment => "Augment",
			Self::Cline => "Cline",
		}
	}
}

/// Detect which AI code editors are configured in the project.
pub fn detect_editors(project_dir: &Path) -> Vec<AiEditor> {
	let mut editors = Vec::new();

	if project_dir.join("CLAUDE.md").exists() {
		editors.push(AiEditor::ClaudeCode);
	}
	if project_dir.join(".cursor").join("rules").is_dir() {
		editors.push(AiEditor::Cursor);
	} else if project_dir.join(".cursorrules").exists() {
		editors.push(AiEditor::CursorRules);
	}
	if project_dir.join(".windsurfrules").exists() {
		editors.push(AiEditor::Windsurf);
	}
	if project_dir
		.join(".github")
		.join("copilot-instructions.md")
		.exists()
	{
		editors.push(AiEditor::GitHubCopilot);
	}
	if project_dir
		.join(".augment")
		.join("instructions.md")
		.exists()
	{
		editors.push(AiEditor::Augment);
	}
	if project_dir.join(".clinerules").exists() {
		editors.push(AiEditor::Cline);
	}

	editors
}

const SKILLS_REFERENCE_MARKER: &str = "<!-- lpm:skills -->";
const SKILLS_REFERENCE_BLOCK: &str = "\n<!-- lpm:skills -->\n## LPM Agent Skills\n\nSee .lpm/skills/ for package-specific Agent Skills and guidelines.\n";

/// Auto-integrate installed skills with detected AI editors.
pub fn auto_integrate_skills(project_dir: &Path) -> Vec<String> {
	let editors = detect_editors(project_dir);
	let skills_dir = project_dir.join(".lpm").join("skills");
	let mut integrated = Vec::new();

	if !skills_dir.exists() {
		return integrated;
	}

	for editor in &editors {
		match editor {
			AiEditor::Cursor => {
				// Symlink skill files into .cursor/rules/
				if let Ok(count) = symlink_skills_to_cursor(project_dir, &skills_dir) {
					if count > 0 {
						integrated.push(format!(
							"{}: {count} skill(s) symlinked to .cursor/rules/",
							editor.name()
						));
					}
				}
			}
			AiEditor::ClaudeCode => {
				if append_skills_reference(project_dir, "CLAUDE.md") {
					integrated.push(format!(
						"{}: added skills reference to CLAUDE.md",
						editor.name()
					));
				}
			}
			AiEditor::CursorRules => {
				if append_skills_reference(project_dir, ".cursorrules") {
					integrated.push(format!(
						"{}: added skills reference to .cursorrules",
						editor.name()
					));
				}
			}
			AiEditor::Windsurf => {
				if append_skills_reference(project_dir, ".windsurfrules") {
					integrated.push(format!(
						"{}: added skills reference to .windsurfrules",
						editor.name()
					));
				}
			}
			AiEditor::GitHubCopilot => {
				if append_skills_reference(project_dir, ".github/copilot-instructions.md") {
					integrated.push(format!(
						"{}: added skills reference",
						editor.name()
					));
				}
			}
			AiEditor::Augment => {
				if append_skills_reference(project_dir, ".augment/instructions.md") {
					integrated.push(format!(
						"{}: added skills reference",
						editor.name()
					));
				}
			}
			AiEditor::Cline => {
				if append_skills_reference(project_dir, ".clinerules") {
					integrated.push(format!(
						"{}: added skills reference to .clinerules",
						editor.name()
					));
				}
			}
		}
	}

	integrated
}

/// Append skills reference block to a markdown/text config file.
/// Returns true if modified, false if already present or failed.
fn append_skills_reference(project_dir: &Path, file_name: &str) -> bool {
	let path = project_dir.join(file_name);
	if !path.exists() {
		return false;
	}

	let content = match std::fs::read_to_string(&path) {
		Ok(c) => c,
		Err(_) => return false,
	};

	// Already has the reference
	if content.contains(SKILLS_REFERENCE_MARKER) {
		return false;
	}

	let mut new_content = content;
	if !new_content.ends_with('\n') {
		new_content.push('\n');
	}
	new_content.push_str(SKILLS_REFERENCE_BLOCK);

	std::fs::write(&path, new_content).is_ok()
}

/// Create symlinks from .cursor/rules/ to .lpm/skills/**/*.md files.
/// Returns the number of symlinks created.
fn symlink_skills_to_cursor(
	project_dir: &Path,
	skills_dir: &Path,
) -> std::io::Result<usize> {
	let cursor_rules = project_dir.join(".cursor").join("rules");
	if !cursor_rules.exists() {
		return Ok(0);
	}

	let mut count = 0;

	// Walk skill subdirectories
	for pkg_entry in std::fs::read_dir(skills_dir)?.flatten() {
		if !pkg_entry.path().is_dir() {
			continue;
		}

		for skill_entry in std::fs::read_dir(pkg_entry.path())?.flatten() {
			let skill_path = skill_entry.path();
			if skill_path
				.extension()
				.map(|e| e == "md")
				.unwrap_or(false)
			{
				let skill_name = skill_path.file_name().unwrap();
				let skill_stem = skill_path
					.file_stem()
					.unwrap_or_default()
					.to_string_lossy();
				if !lpm_common::is_safe_skill_name(&skill_stem) {
					tracing::warn!(
						"skipping editor symlink for unsafe skill name: {}",
						skill_stem
					);
					continue;
				}

				let pkg_name = pkg_entry.file_name();
				let safe_pkg =
					lpm_common::sanitize_path_component(&pkg_name.to_string_lossy());
				// Unique name: {pkg}--{skill}.md
				let link_name = format!(
					"{}--{}",
					safe_pkg,
					skill_name.to_string_lossy()
				);
				let link_path = cursor_rules.join(&link_name);

				if link_path.exists() || link_path.symlink_metadata().is_ok() {
					continue; // Already linked
				}

				// Relative path from .cursor/rules/ to .lpm/skills/{pkg}/{skill}.md
				let rel_target = diff_paths(&skill_path, &cursor_rules)
					.unwrap_or_else(|| skill_path.clone());

				#[cfg(unix)]
				{
					match std::os::unix::fs::symlink(&rel_target, &link_path) {
						Ok(()) => count += 1,
						Err(e) => {
							tracing::debug!("failed to create symlink {}: {e}", link_path.display());
						}
					}
				}
				#[cfg(windows)]
				{
					match std::fs::copy(&skill_path, &link_path) {
						Ok(_) => count += 1,
						Err(e) => {
							tracing::debug!("failed to copy skill to {}: {e}", link_path.display());
						}
					}
				}
			}
		}
	}

	Ok(count)
}

/// Remove editor integration for a specific package's skills.
pub fn remove_editor_skills(project_dir: &Path, package_short_name: &str) {
	// Remove Cursor symlinks
	let cursor_rules = project_dir.join(".cursor").join("rules");
	if cursor_rules.is_dir() {
		if let Ok(entries) = std::fs::read_dir(&cursor_rules) {
			for entry in entries.flatten() {
				let name = entry.file_name().to_string_lossy().to_string();
				if name.starts_with(&format!("{package_short_name}--")) {
					let _ = std::fs::remove_file(entry.path());
				}
			}
		}
	}
	// Note: markdown reference blocks are generic (not per-package), so we don't remove them
}

/// Compute the relative path from `base` to `target`.
///
/// Minimal implementation that avoids an external dependency for a single function.
/// Both paths must be absolute or both relative for correct results.
fn diff_paths(target: &Path, base: &Path) -> Option<PathBuf> {
	let target = normalize_path(target);
	let base = normalize_path(base);

	let mut target_iter = target.components().peekable();
	let mut base_iter = base.components().peekable();

	// Skip the common prefix
	while let (Some(t), Some(b)) = (target_iter.peek(), base_iter.peek()) {
		if t != b {
			break;
		}
		target_iter.next();
		base_iter.next();
	}

	// For each remaining component in base, go up one level
	let mut result = PathBuf::new();
	for _ in base_iter {
		result.push("..");
	}

	// Then descend into the remaining target components
	for comp in target_iter {
		result.push(comp);
	}

	if result.as_os_str().is_empty() {
		None
	} else {
		Some(result)
	}
}

/// Normalize a path by resolving `.` and `..` without touching the filesystem.
fn normalize_path(path: &Path) -> PathBuf {
	use std::path::Component;
	let mut components = Vec::new();
	for comp in path.components() {
		match comp {
			Component::CurDir => {}
			Component::ParentDir => {
				if let Some(Component::Normal(_)) =
					components.last().map(|c: &Component| *c)
				{
					components.pop();
				} else {
					components.push(comp);
				}
			}
			_ => components.push(comp),
		}
	}
	components.iter().collect()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	#[test]
	fn detect_editors_claude_code() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("CLAUDE.md"), "# Rules").unwrap();

		let editors = detect_editors(dir.path());
		assert_eq!(editors, vec![AiEditor::ClaudeCode]);
	}

	#[test]
	fn detect_editors_cursor_rules_dir() {
		let dir = tempfile::tempdir().unwrap();
		fs::create_dir_all(dir.path().join(".cursor").join("rules")).unwrap();

		let editors = detect_editors(dir.path());
		assert_eq!(editors, vec![AiEditor::Cursor]);
	}

	#[test]
	fn detect_editors_nothing() {
		let dir = tempfile::tempdir().unwrap();
		let editors = detect_editors(dir.path());
		assert!(editors.is_empty());
	}

	#[test]
	fn append_skills_reference_adds_block() {
		let dir = tempfile::tempdir().unwrap();
		fs::write(dir.path().join("CLAUDE.md"), "# Project\n").unwrap();

		let result = append_skills_reference(dir.path(), "CLAUDE.md");
		assert!(result);

		let content = fs::read_to_string(dir.path().join("CLAUDE.md")).unwrap();
		assert!(content.contains(SKILLS_REFERENCE_MARKER));
		assert!(content.contains("See .lpm/skills/"));
	}

	#[test]
	fn append_skills_reference_no_duplicate() {
		let dir = tempfile::tempdir().unwrap();
		let initial = format!("# Project\n{SKILLS_REFERENCE_BLOCK}");
		fs::write(dir.path().join("CLAUDE.md"), &initial).unwrap();

		let result = append_skills_reference(dir.path(), "CLAUDE.md");
		assert!(!result);
	}

	#[test]
	fn remove_editor_skills_cleans_cursor_symlinks() {
		let dir = tempfile::tempdir().unwrap();
		let cursor_rules = dir.path().join(".cursor").join("rules");
		fs::create_dir_all(&cursor_rules).unwrap();

		// Create fake symlink entries (just regular files for the test)
		fs::write(
			cursor_rules.join("owner.pkg--guide.md"),
			"skill content",
		)
		.unwrap();
		fs::write(
			cursor_rules.join("owner.pkg--api.md"),
			"skill content",
		)
		.unwrap();
		fs::write(
			cursor_rules.join("other.pkg--guide.md"),
			"other content",
		)
		.unwrap();

		remove_editor_skills(dir.path(), "owner.pkg");

		// owner.pkg files should be gone
		assert!(!cursor_rules.join("owner.pkg--guide.md").exists());
		assert!(!cursor_rules.join("owner.pkg--api.md").exists());
		// other.pkg file should remain
		assert!(cursor_rules.join("other.pkg--guide.md").exists());
	}

	#[test]
	fn diff_paths_basic() {
		let result = diff_paths(
			Path::new("/a/b/c/d.md"),
			Path::new("/a/b/e"),
		);
		assert_eq!(result, Some(PathBuf::from("../c/d.md")));
	}

	#[cfg(unix)]
	#[test]
	fn symlink_skips_unsafe_skill_name() {
		let dir = tempfile::tempdir().unwrap();
		let skills_dir = dir.path().join(".lpm").join("skills");
		let pkg_dir = skills_dir.join("owner.pkg");
		fs::create_dir_all(&pkg_dir).unwrap();

		// Create a skill file with a traversal name
		fs::write(pkg_dir.join("..%2F..%2Fevil.md"), "bad content").unwrap();
		// Create a safe skill file
		fs::write(pkg_dir.join("good-skill.md"), "good content").unwrap();

		let cursor_rules = dir.path().join(".cursor").join("rules");
		fs::create_dir_all(&cursor_rules).unwrap();

		let count = symlink_skills_to_cursor(dir.path(), &skills_dir).unwrap();
		// Only the good skill should be symlinked (..%2F..%2Fevil contains %)
		assert_eq!(count, 1);
		assert!(cursor_rules.join("owner.pkg--good-skill.md").exists());
	}
}
