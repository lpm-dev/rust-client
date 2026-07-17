use std::collections::BTreeSet;
use std::path::Path;

use lpm_common::LpmError;
use lpm_security::skill_security::{self, SkillSecurityIssue};
use sha2::{Digest, Sha256};

use super::package;

const MAX_SKILL_SIZE: u64 = 15 * 1024;
const MAX_TOTAL_SIZE: u64 = 100 * 1024;
const MAX_SKILL_COUNT: usize = 10;
const MIN_BODY_LENGTH: usize = 100;

#[derive(Debug)]
pub(crate) struct LocatedSecurityIssue {
    pub(crate) path: String,
    pub(crate) issue: SkillSecurityIssue,
}

#[derive(Debug, Default)]
pub(crate) struct ValidationReport {
    pub(crate) directory_found: bool,
    pub(crate) valid_files: Vec<String>,
    pub(crate) errors: Vec<String>,
    pub(crate) security_issues: Vec<LocatedSecurityIssue>,
    pub(crate) total_size_bytes: u64,
    pub(crate) ignored_package_sets: usize,
    authored_file_count: usize,
}

impl ValidationReport {
    pub(crate) fn is_valid(&self) -> bool {
        self.errors.is_empty() && self.security_issues.is_empty()
    }

    pub(crate) fn error_count(&self) -> usize {
        self.errors.len() + self.security_issues.len()
    }
}

pub(crate) fn validate_directory(skills_dir: &Path) -> Result<ValidationReport, LpmError> {
    let metadata = match std::fs::symlink_metadata(skills_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ValidationReport::default());
        }
        Err(error) => return Err(LpmError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LpmError::Registry(format!(
            "package skill path is not a regular directory: {}",
            skills_dir.display()
        )));
    }

    let mut report = ValidationReport {
        directory_found: true,
        ..ValidationReport::default()
    };
    let mut names = BTreeSet::new();
    for entry in sorted_entries(skills_dir)? {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            report.errors.push(format!(
                "{}: package skill entries must not be symlinks",
                relative_display(skills_dir, &path)
            ));
        } else if metadata.is_file() {
            if path.extension().is_some_and(|extension| extension == "md") {
                validate_file(skills_dir, &path, metadata.len(), &mut names, &mut report)?;
            }
        } else if metadata.is_dir() {
            if package::is_materialized_directory(&path) {
                report.ignored_package_sets += 1;
            } else {
                collect_nested_markdown_errors(skills_dir, &path, &mut report.errors)?;
            }
        }
    }

    if report.authored_file_count > MAX_SKILL_COUNT {
        report.errors.push(format!(
            "too many package skills ({}); maximum is {MAX_SKILL_COUNT}",
            report.authored_file_count
        ));
    }
    if report.total_size_bytes > MAX_TOTAL_SIZE {
        report.errors.push(format!(
            "total package skills size {} bytes exceeds 100KB limit",
            report.total_size_bytes
        ));
    }

    Ok(report)
}

fn validate_file(
    skills_dir: &Path,
    path: &Path,
    size: u64,
    names: &mut BTreeSet<String>,
    report: &mut ValidationReport,
) -> Result<(), LpmError> {
    let display = relative_display(skills_dir, path);
    report.authored_file_count += 1;
    report.total_size_bytes = report.total_size_bytes.saturating_add(size);
    let error_count = report.errors.len();
    let security_count = report.security_issues.len();

    if size > MAX_SKILL_SIZE {
        report
            .errors
            .push(format!("{display}: exceeds 15KB limit ({size} bytes)"));
        return Ok(());
    }

    let content = std::fs::read_to_string(path)?;
    let (meta, body, frontmatter_errors) = skill_security::parse_skill_frontmatter(&content);
    if !frontmatter_errors.is_empty() {
        report.errors.extend(
            frontmatter_errors
                .into_iter()
                .map(|error| format!("{display}: {error}")),
        );
        return Ok(());
    }

    if body.trim().encode_utf16().count() < MIN_BODY_LENGTH {
        report.errors.push(format!(
            "{display}: content is too short (minimum {MIN_BODY_LENGTH} characters)"
        ));
    }

    if let Some(name) = meta.name
        && !names.insert(name.clone())
    {
        report
            .errors
            .push(format!("{display}: duplicate skill name `{name}`"));
    }

    report.security_issues.extend(
        skill_security::scan_skill_content(&content)
            .into_iter()
            .map(|issue| LocatedSecurityIssue {
                path: display.clone(),
                issue,
            }),
    );

    if report.errors.len() == error_count && report.security_issues.len() == security_count {
        report.valid_files.push(display);
    }
    Ok(())
}

fn collect_nested_markdown_errors(
    skills_dir: &Path,
    directory: &Path,
    errors: &mut Vec<String>,
) -> Result<(), LpmError> {
    for entry in sorted_entries(directory)? {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            errors.push(format!(
                "{}: package skill entries must not be symlinks",
                relative_display(skills_dir, &path)
            ));
        } else if metadata.is_dir() {
            collect_nested_markdown_errors(skills_dir, &path, errors)?;
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension == "md")
        {
            errors.push(format!(
                "{}: package skills must be direct .md files under .lpm/skills/",
                relative_display(skills_dir, &path)
            ));
        }
    }
    Ok(())
}

fn sorted_entries(directory: &Path) -> Result<Vec<std::fs::DirEntry>, LpmError> {
    let mut entries = std::fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    Ok(entries)
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

pub(crate) fn compute_digest(skills_dir: &Path) -> Result<String, LpmError> {
    let mut entries = Vec::new();
    for entry in sorted_entries(skills_dir)? {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || path.extension().is_none_or(|extension| extension != "md")
        {
            continue;
        }
        let content = std::fs::read_to_string(&path)?;
        let (meta, _, errors) = skill_security::parse_skill_frontmatter(&content);
        if !errors.is_empty() {
            return Err(LpmError::Registry(format!(
                "cannot compute package skill digest for {}: {}",
                relative_display(skills_dir, &path),
                errors.join(", ")
            )));
        }
        let name = meta.name.ok_or_else(|| {
            LpmError::Registry(format!(
                "cannot compute package skill digest for {}: missing skill name",
                relative_display(skills_dir, &path)
            ))
        })?;
        entries.push((name, content.into_bytes()));
    }

    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    for (name, content) in entries {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(content);
        hasher.update(b"\0");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_skill(name: &str) -> String {
        format!(
            "---\nname: {name}\ndescription: A complete package skill for validation\n---\n# Guide\n\n{}",
            "This package guidance explains the supported workflow with concrete examples and enough detail for an agent to use it correctly."
        )
    }

    #[test]
    fn validate_directory_ignores_manifest_owned_consumer_sets() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        std::fs::create_dir_all(&skills).unwrap();
        std::fs::write(skills.join("author.md"), valid_skill("author")).unwrap();
        package::materialize(
            project.path(),
            "owner.package",
            Some("1.0.0"),
            &[lpm_registry::Skill {
                name: "consumer".into(),
                description: None,
                version: None,
                globs: Vec::new(),
                content: Some(valid_skill("consumer")),
                raw_content: None,
                size_bytes: None,
            }],
        )
        .unwrap();

        let report = validate_directory(&skills).unwrap();

        assert_eq!(report.ignored_package_sets, 1);
        assert_eq!(report.valid_files, vec!["author.md"]);
    }

    #[test]
    fn validate_directory_rejects_more_than_ten_skills() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        std::fs::create_dir_all(&skills).unwrap();
        for index in 0..=MAX_SKILL_COUNT {
            let name = format!("skill-{index}");
            std::fs::write(skills.join(format!("{name}.md")), valid_skill(&name)).unwrap();
        }

        let report = validate_directory(&skills).unwrap();

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("maximum is 10"))
        );
    }

    #[test]
    fn validate_directory_rejects_non_array_globs() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        std::fs::create_dir_all(&skills).unwrap();
        std::fs::write(
            skills.join("invalid.md"),
            format!(
                "---\nname: invalid\ndescription: A complete package skill for validation\nglobs: src/**/*.ts\n---\n# Guide\n\n{}",
                "This package guidance explains the supported workflow with concrete examples and enough detail for an agent to use it correctly."
            ),
        )
        .unwrap();

        let report = validate_directory(&skills).unwrap();

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("globs field must be an array"))
        );
    }

    #[test]
    fn validate_directory_matches_registry_block_scalar_description_behavior() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        std::fs::create_dir_all(&skills).unwrap();
        std::fs::write(
            skills.join("invalid.md"),
            format!(
                "---\nname: invalid\ndescription: >\n  A complete package skill for validation\n---\n# Guide\n\n{}",
                "This package guidance explains the supported workflow with concrete examples and enough detail for an agent to use it correctly."
            ),
        )
        .unwrap();

        let report = validate_directory(&skills).unwrap();

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("description too short"))
        );
    }

    #[test]
    fn validate_directory_trims_body_before_minimum_length_check() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        std::fs::create_dir_all(&skills).unwrap();
        std::fs::write(
            skills.join("short.md"),
            "---\nname: short\ndescription: A complete package skill for validation\n---\nshort                                                                                                    ",
        )
        .unwrap();

        let report = validate_directory(&skills).unwrap();

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("content is too short"))
        );
    }
}
