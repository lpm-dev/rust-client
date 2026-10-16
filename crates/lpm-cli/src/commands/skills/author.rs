//! A package's authored skills: the direct `.md` files in `lpm-skills/` at
//! the published root, checked with [`lpm_skill`]'s rules before publish.
//! They ship in the tarball at the same path. `.lpm/` is never published,
//! so skills left in `.lpm/skills/` by older versions are reported until
//! they move.

use std::io::Read as _;
use std::path::Path;

use lpm_common::LpmError;
use lpm_skill::{AUTHORED_SKILLS_DIR, LocatedSecurityIssue, SkillEntry};
use sha2::{Digest, Sha256};

const SKILLS_PREFIX: &str = "lpm-skills/";
/// How deep the walk for Markdown in subdirectories of `lpm-skills/` goes.
const MAX_NESTING: usize = 16;

#[derive(Debug, Default)]
pub(crate) struct ValidationReport {
    pub(crate) directory_found: bool,
    pub(crate) valid_files: Vec<String>,
    pub(crate) errors: Vec<String>,
    pub(crate) security_issues: Vec<LocatedSecurityIssue>,
    pub(crate) total_size_bytes: u64,
    pub(crate) validated_files: Vec<ValidatedSkillFile>,
}

#[derive(Debug)]
pub(crate) struct ValidatedSkillFile {
    pub(crate) archive_path: String,
    pub(crate) name: String,
    pub(crate) content: Vec<u8>,
}

impl ValidationReport {
    pub(crate) fn is_valid(&self) -> bool {
        self.errors.is_empty() && self.security_issues.is_empty()
    }

    pub(crate) fn error_count(&self) -> usize {
        self.errors.len() + self.security_issues.len()
    }
}

/// Checks the authored skills a publish of the project at `project_dir`
/// would ship: those of `publishConfig.directory` when `package.json`
/// names one, else of the project.
pub(crate) fn validate_project(project_dir: &Path) -> Result<ValidationReport, LpmError> {
    let canonical = project_dir.canonicalize().map_err(LpmError::Io)?;
    let root = crate::commands::publish_common::open_tarball_source_root(&canonical)?;
    let directory = match lpm_common::read_text_file_capped_nofollow(
        &canonical.join("package.json"),
        lpm_common::CONFIG_FILE_SIZE_CAP_BYTES,
    ) {
        Ok(content) => {
            let pkg_json: serde_json::Value = serde_json::from_str(lpm_common::strip_utf8_bom_str(
                &content,
            ))
            .map_err(|error| LpmError::Registry(format!("invalid package.json: {error}")))?;
            crate::commands::publish_common::publish_directory(&pkg_json)?
        }
        Err(lpm_common::BoundedReadError::NotFound { .. }) => None,
        Err(error) => return Err(LpmError::Registry(error.to_string())),
    };
    let Some(relative) = directory else {
        return validate_publish_directory(&root, project_dir);
    };
    let published_path = project_dir.join(&relative);
    let published = crate::commands::publish_common::open_cap_directory_path(&root, &relative)?
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "package.json publishConfig.directory does not exist or is not a safe directory: {}",
                published_path.display()
            ))
        })?;
    validate_publish_directory(&published, &published_path)
}

/// Checks the authored skills in an open published root. `project_path`
/// names the root in errors.
pub(crate) fn validate_publish_directory(
    project_root: &cap_std::fs::Dir,
    project_path: &Path,
) -> Result<ValidationReport, LpmError> {
    use cap_fs_ext::DirExt as _;

    let mut host_errors = skills_left_in_lpm_state(project_root)?;
    let skills_dir = match project_root.open_dir_nofollow(AUTHORED_SKILLS_DIR) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            host_errors.sort();
            return Ok(ValidationReport {
                errors: host_errors,
                ..ValidationReport::default()
            });
        }
        Err(_) => {
            return Err(LpmError::Registry(format!(
                "package skill path is unsafe: {}",
                project_path.join(AUTHORED_SKILLS_DIR).display()
            )));
        }
    };
    let mut entries = Vec::new();
    collect_entries(&skills_dir, "", 0, &mut entries, &mut host_errors)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let mut skill_files = 0usize;
    for entry in &mut entries {
        if !lpm_skill::is_skill_file(&entry.path) {
            continue;
        }
        skill_files += 1;
        if skill_files > lpm_skill::MAX_SKILL_COUNT + 1 {
            break;
        }
        if lpm_skill::reads_content(&entry.path, entry.size) {
            entry.content = Some(read_skill_file(&skills_dir, &entry.path, entry.size)?);
        }
    }
    let report = lpm_skill::validate(SKILLS_PREFIX, &entries);

    let mut errors = host_errors;
    errors.extend(report.errors);
    errors.sort();
    let validated_files = if errors.is_empty() {
        report
            .skills
            .iter()
            .map(|skill| ValidatedSkillFile {
                archive_path: format!("{SKILLS_PREFIX}{}", skill.path),
                name: skill.name.clone(),
                content: skill.raw.clone().into_bytes(),
            })
            .collect()
    } else {
        Vec::new()
    };
    Ok(ValidationReport {
        directory_found: true,
        valid_files: validated_files
            .iter()
            .map(|skill| skill.archive_path.clone())
            .collect(),
        errors,
        security_issues: report.security_issues,
        total_size_bytes: report.total_size,
        validated_files,
    })
}

/// Errors for skills an older version had authors keep directly in
/// `.lpm/skills/`, which is never published.
fn skills_left_in_lpm_state(project_root: &cap_std::fs::Dir) -> Result<Vec<String>, LpmError> {
    use cap_fs_ext::DirExt as _;

    let Ok(state) = project_root.open_dir_nofollow(lpm_common::PROJECT_STATE_DIR) else {
        return Ok(Vec::new());
    };
    let Ok(skills) = state.open_dir_nofollow("skills") else {
        return Ok(Vec::new());
    };
    let mut errors = Vec::new();
    for entry in skills.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let metadata = skills.symlink_metadata(name)?;
        if metadata.is_file()
            && !crate::commands::publish_common::metadata_is_link_or_reparse(&metadata)
            && lpm_skill::is_skill_file(name)
        {
            errors.push(format!(
                ".lpm/skills/{name}: authored skills live in lpm-skills/ — move it to lpm-skills/{name} (.lpm/ is never published or committed)"
            ));
        }
    }
    Ok(errors)
}

fn collect_entries(
    directory: &cap_std::fs::Dir,
    relative: &str,
    depth: usize,
    entries: &mut Vec<SkillEntry>,
    errors: &mut Vec<String>,
) -> Result<(), LpmError> {
    use cap_fs_ext::DirExt as _;

    for entry in directory.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            errors.push(format!(
                "{SKILLS_PREFIX}{relative}{}: skill file names must be UTF-8",
                name.to_string_lossy()
            ));
            continue;
        };
        let path = format!("{relative}{name}");
        let metadata = directory.symlink_metadata(name)?;
        if crate::commands::publish_common::metadata_is_link_or_reparse(&metadata) {
            errors.push(format!(
                "{SKILLS_PREFIX}{path}: package skill entries must not be symlinks"
            ));
        } else if metadata.is_dir() {
            if depth >= MAX_NESTING {
                errors.push(format!(
                    "{SKILLS_PREFIX}{path}: nested too deeply under {SKILLS_PREFIX}"
                ));
                continue;
            }
            let nested = directory.open_dir_nofollow(name).map_err(LpmError::Io)?;
            collect_entries(&nested, &format!("{path}/"), depth + 1, entries, errors)?;
        } else if metadata.is_file()
            && (lpm_skill::is_skill_file(&path) || lpm_skill::is_nested_markdown(&path))
        {
            entries.push(SkillEntry {
                path,
                size: metadata.len(),
                content: None,
            });
        }
    }
    Ok(())
}

fn read_skill_file(
    skills_dir: &cap_std::fs::Dir,
    path: &str,
    size: u64,
) -> Result<Vec<u8>, LpmError> {
    let (file, _) = crate::commands::publish_common::open_tarball_source_file(
        skills_dir,
        Path::new(path),
        &format!("{SKILLS_PREFIX}{path}"),
    )?;
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(lpm_skill::MAX_SKILL_SIZE + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
pub(crate) fn compute_digest(project_dir: &Path) -> Result<String, LpmError> {
    let report = validate_project(project_dir)?;
    if !report.is_valid() {
        return Err(LpmError::Registry(format!(
            "cannot compute package skill digest: {}",
            report.errors.join(", ")
        )));
    }
    Ok(compute_validated_digest(&report.validated_files))
}

pub(crate) fn compute_validated_digest(skills: &[ValidatedSkillFile]) -> String {
    let mut entries = skills.iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let mut hasher = Sha256::new();
    for skill in entries {
        hasher.update(skill.name.as_bytes());
        hasher.update(b"\0");
        hasher.update(&skill.content);
        hasher.update(b"\0");
    }
    format!("{:x}", hasher.finalize())
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

    fn project_with_skills(files: &[(&str, String)]) -> tempfile::TempDir {
        let project = tempfile::tempdir().unwrap();
        for (path, content) in files {
            let path = project.path().join("lpm-skills").join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        project
    }

    #[test]
    fn validates_direct_markdown_files_in_lpm_skills() {
        let project = project_with_skills(&[
            ("usage.md", valid_skill("usage")),
            ("notes.txt", "kept out of the package".into()),
        ]);

        let report = validate_project(project.path()).unwrap();

        assert!(report.is_valid(), "{:?}", report.errors);
        assert_eq!(report.valid_files, ["lpm-skills/usage.md"]);
        assert_eq!(
            report.validated_files[0].archive_path,
            "lpm-skills/usage.md"
        );
        assert_eq!(report.validated_files[0].name, "usage");
    }

    #[test]
    fn validates_the_skills_of_the_directory_publish_packs() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("package.json"),
            r#"{"name":"pkg","version":"1.0.0","publishConfig":{"directory":"dist"}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(project.path().join("lpm-skills")).unwrap();
        std::fs::write(
            project.path().join("lpm-skills/usage.md"),
            valid_skill("usage"),
        )
        .unwrap();
        std::fs::create_dir_all(project.path().join("dist/lpm-skills")).unwrap();
        std::fs::write(
            project.path().join("dist/lpm-skills/broken.md"),
            "no frontmatter\n",
        )
        .unwrap();

        let report = validate_project(project.path()).unwrap();

        assert!(!report.is_valid());
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("broken.md")),
            "{:?}",
            report.errors
        );
    }

    #[test]
    fn a_project_without_lpm_skills_has_nothing_to_validate() {
        let project = tempfile::tempdir().unwrap();

        let report = validate_project(project.path()).unwrap();

        assert!(!report.directory_found);
        assert!(report.is_valid());
    }

    #[test]
    fn reports_skills_left_in_lpm_state_and_ignores_installed_sets() {
        let project = tempfile::tempdir().unwrap();
        let state = project.path().join(".lpm/skills");
        std::fs::create_dir_all(state.join("owner.package")).unwrap();
        std::fs::write(state.join("owner.package/usage.md"), valid_skill("usage")).unwrap();
        std::fs::write(state.join("guide.md"), valid_skill("guide")).unwrap();

        let report = validate_project(project.path()).unwrap();

        assert_eq!(
            report.errors,
            [
                ".lpm/skills/guide.md: authored skills live in lpm-skills/ — move it to lpm-skills/guide.md (.lpm/ is never published or committed)"
            ]
        );
    }

    #[test]
    fn markdown_in_a_subdirectory_fails_validation() {
        let project = project_with_skills(&[
            ("usage.md", valid_skill("usage")),
            ("guides/intro.md", valid_skill("intro")),
        ]);

        let report = validate_project(project.path()).unwrap();

        assert_eq!(
            report.errors,
            [
                "lpm-skills/guides/intro.md: package skills must be direct .md files under lpm-skills/"
            ]
        );
        assert!(report.validated_files.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_skill_fails_validation() {
        let project = project_with_skills(&[("usage.md", valid_skill("usage"))]);
        std::os::unix::fs::symlink(
            project.path().join("lpm-skills/usage.md"),
            project.path().join("lpm-skills/linked.md"),
        )
        .unwrap();

        let report = validate_project(project.path()).unwrap();

        assert_eq!(
            report.errors,
            ["lpm-skills/linked.md: package skill entries must not be symlinks"]
        );
    }

    #[test]
    fn rejects_more_than_ten_skills_and_reads_at_most_one_more() {
        let files: Vec<(String, String)> = (0..=lpm_skill::MAX_SKILL_COUNT + 3)
            .map(|index| {
                let name = format!("skill-{index:02}");
                (format!("{name}.md"), valid_skill(&name))
            })
            .collect();
        let files: Vec<(&str, String)> = files
            .iter()
            .map(|(path, content)| (path.as_str(), content.clone()))
            .collect();
        let project = project_with_skills(&files);

        let report = validate_project(project.path()).unwrap();

        assert!(
            report
                .errors
                .contains(&"too many package skills; maximum is 10".to_string())
        );
        assert!(report.validated_files.is_empty());
    }

    #[test]
    fn digest_depends_on_names_and_content() {
        let first = project_with_skills(&[("usage.md", valid_skill("usage"))]);
        let second = project_with_skills(&[("usage.md", valid_skill("usage"))]);
        let changed = project_with_skills(&[("usage.md", valid_skill("usage") + " more")]);

        assert_eq!(
            compute_digest(first.path()).unwrap(),
            compute_digest(second.path()).unwrap()
        );
        assert_ne!(
            compute_digest(first.path()).unwrap(),
            compute_digest(changed.path()).unwrap()
        );
    }
}
