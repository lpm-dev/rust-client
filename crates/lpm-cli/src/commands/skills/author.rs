use std::collections::BTreeSet;
use std::io::Read as _;
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
    pub(crate) validated_files: Vec<ValidatedSkillFile>,
    authored_file_count: usize,
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

    let canonical = skills_dir.canonicalize().map_err(LpmError::Io)?;
    let source_dir = crate::commands::publish_common::open_tarball_source_root(&canonical)?;
    validate_open_directory(&source_dir)
}

pub(crate) fn validate_publish_directory(
    project_root: &cap_std::fs::Dir,
    project_path: &Path,
) -> Result<ValidationReport, LpmError> {
    use cap_fs_ext::DirExt as _;

    let lpm_dir = match project_root.open_dir_nofollow(".lpm") {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ValidationReport::default());
        }
        Err(_) => {
            return Err(LpmError::Registry(format!(
                "package skill path is unsafe: {}",
                project_path.join(".lpm").display()
            )));
        }
    };
    let skills_dir = match lpm_dir.open_dir_nofollow("skills") {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ValidationReport::default());
        }
        Err(_) => {
            return Err(LpmError::Registry(format!(
                "package skill path is unsafe: {}",
                project_path.join(".lpm/skills").display()
            )));
        }
    };
    validate_open_directory(&skills_dir)
}

fn validate_open_directory(skills_dir: &cap_std::fs::Dir) -> Result<ValidationReport, LpmError> {
    use cap_fs_ext::DirExt as _;

    let mut report = ValidationReport {
        directory_found: true,
        ..ValidationReport::default()
    };
    let mut names = BTreeSet::new();
    for entry in skills_dir.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let relative = Path::new(&name);
        let display = relative.display().to_string();
        let metadata = skills_dir.symlink_metadata(relative)?;
        if crate::commands::publish_common::metadata_is_link_or_reparse(&metadata) {
            report.errors.push(format!(
                "{}: package skill entries must not be symlinks",
                display
            ));
        } else if metadata.is_file() {
            if relative
                .extension()
                .is_some_and(|extension| extension == "md")
            {
                let (file, size) = crate::commands::publish_common::open_tarball_source_file(
                    skills_dir,
                    relative,
                    &format!(".lpm/skills/{display}"),
                )?;
                validate_opened_file(file, &display, size, &mut names, &mut report)?;
                if report.authored_file_count > MAX_SKILL_COUNT {
                    break;
                }
            }
        } else if metadata.is_dir() {
            let directory = skills_dir
                .open_dir_nofollow(relative)
                .map_err(LpmError::Io)?;
            if is_materialized_directory(&directory, &name) {
                report.ignored_package_sets += 1;
            } else {
                collect_nested_markdown_errors_from_dir(&directory, relative, &mut report.errors)?;
            }
        }
    }

    if report.authored_file_count > MAX_SKILL_COUNT {
        report.errors.push(format!(
            "too many package skills; maximum is {MAX_SKILL_COUNT}"
        ));
    }
    if report.total_size_bytes > MAX_TOTAL_SIZE {
        report.errors.push(format!(
            "total package skills size {} bytes exceeds 100KB limit",
            report.total_size_bytes
        ));
    }

    report.valid_files.sort();
    report
        .validated_files
        .sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    report.errors.sort();
    report.security_issues.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.issue.line_number.cmp(&right.issue.line_number))
            .then_with(|| left.issue.rule_id.cmp(&right.issue.rule_id))
    });

    Ok(report)
}

pub(crate) fn is_authored_skill_path(path: &Path, skills_dir: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(skills_dir) else {
        return false;
    };
    let mut components = relative.components();
    let Some(std::path::Component::Normal(file_name)) = components.next() else {
        return false;
    };
    components.next().is_none()
        && Path::new(file_name)
            .extension()
            .is_some_and(|extension| extension == "md")
}

fn validate_opened_file(
    mut file: std::fs::File,
    display: &str,
    size: u64,
    names: &mut BTreeSet<String>,
    report: &mut ValidationReport,
) -> Result<(), LpmError> {
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

    let mut bytes = Vec::with_capacity(size as usize);
    file.by_ref()
        .take(MAX_SKILL_SIZE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SKILL_SIZE {
        report.total_size_bytes = report
            .total_size_bytes
            .saturating_sub(size)
            .saturating_add(bytes.len() as u64);
        report.errors.push(format!(
            "{display}: exceeds 15KB limit ({} bytes)",
            bytes.len()
        ));
        return Ok(());
    }
    let content = std::str::from_utf8(&bytes).map_err(|error| {
        LpmError::Registry(format!(
            "{display}: package skill is not valid UTF-8: {error}"
        ))
    })?;
    let (meta, body, frontmatter_errors) = skill_security::parse_skill_frontmatter(content);
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

    let Some(parsed_name) = meta.name else {
        report
            .errors
            .push(format!("{display}: package skill name is missing"));
        return Ok(());
    };
    if !names.insert(parsed_name.clone()) {
        report
            .errors
            .push(format!("{display}: duplicate skill name `{parsed_name}`"));
    }

    report
        .security_issues
        .extend(
            skill_security::scan_skill_content(content)
                .into_iter()
                .map(|issue| LocatedSecurityIssue {
                    path: display.to_string(),
                    issue,
                }),
        );

    if report.errors.len() == error_count
        && report.security_issues.len() == security_count
        && report.authored_file_count <= MAX_SKILL_COUNT
        && report.total_size_bytes <= MAX_TOTAL_SIZE
    {
        report.valid_files.push(display.to_string());
        report.validated_files.push(ValidatedSkillFile {
            archive_path: format!(".lpm/skills/{display}"),
            name: parsed_name,
            content: bytes,
        });
    }
    Ok(())
}

fn is_materialized_directory(directory: &cap_std::fs::Dir, name: &std::ffi::OsStr) -> bool {
    let Some(package_name) = name.to_str() else {
        return false;
    };
    let Ok((manifest_file, manifest_size)) =
        crate::commands::publish_common::open_tarball_source_file(
            directory,
            Path::new(package::MANIFEST_FILE),
            package::MANIFEST_FILE,
        )
    else {
        return false;
    };
    if manifest_size > package::MAX_MANIFEST_SIZE {
        return false;
    }
    let Ok(content) = lpm_common::read_text_file_capped_from_open_file_with_known_size(
        manifest_file,
        Path::new(package::MANIFEST_FILE),
        package::MAX_MANIFEST_SIZE,
        manifest_size,
    ) else {
        return false;
    };
    let Ok(manifest) = serde_json::from_str::<package::PackageSkillsManifest>(&content) else {
        return false;
    };
    if manifest.schema_version != package::MANIFEST_VERSION
        || manifest.package != package_name
        || !manifest
            .skills
            .keys()
            .all(|skill| lpm_common::is_safe_skill_name(skill))
    {
        return false;
    }

    let mut seen = BTreeSet::new();
    let Ok(entries) = directory.entries() else {
        return false;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        if name == package::MANIFEST_FILE {
            continue;
        }
        let relative = Path::new(&name);
        let Ok(metadata) = directory.symlink_metadata(relative) else {
            return false;
        };
        if crate::commands::publish_common::metadata_is_link_or_reparse(&metadata)
            || !metadata.is_file()
            || relative
                .extension()
                .is_none_or(|extension| extension != "md")
        {
            return false;
        }
        let Some(skill_name) = relative.file_stem().and_then(|name| name.to_str()) else {
            return false;
        };
        let Some(expected_digest) = manifest.skills.get(skill_name) else {
            return false;
        };
        let Ok((file, size)) = crate::commands::publish_common::open_tarball_source_file(
            directory,
            relative,
            &relative.display().to_string(),
        ) else {
            return false;
        };
        if digest_opened_file(file, size).as_deref() != Some(expected_digest.as_str()) {
            return false;
        }
        seen.insert(skill_name.to_string());
    }
    seen.len() == manifest.skills.len()
}

fn digest_opened_file(mut file: std::fs::File, expected_size: u64) -> Option<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut remaining = expected_size;
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64)).ok()?;
        let read = file.read(&mut buffer[..limit]).ok()?;
        if read == 0 {
            return None;
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    if file.read(&mut buffer[..1]).ok()? != 0 {
        return None;
    }
    Some(format!("{:x}", hasher.finalize()))
}

fn collect_nested_markdown_errors_from_dir(
    directory: &cap_std::fs::Dir,
    relative_root: &Path,
    errors: &mut Vec<String>,
) -> Result<(), LpmError> {
    use cap_fs_ext::DirExt as _;

    for entry in directory.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let relative = Path::new(&name);
        let path = relative_root.join(relative);
        let metadata = directory.symlink_metadata(relative)?;
        if crate::commands::publish_common::metadata_is_link_or_reparse(&metadata) {
            errors.push(format!(
                "{}: package skill entries must not be symlinks",
                path.display()
            ));
        } else if metadata.is_dir() {
            let nested = directory.open_dir_nofollow(relative)?;
            collect_nested_markdown_errors_from_dir(&nested, &path, errors)?;
        } else if metadata.is_file()
            && relative
                .extension()
                .is_some_and(|extension| extension == "md")
        {
            errors.push(format!(
                "{}: package skills must be direct .md files under .lpm/skills/",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn sorted_entries(directory: &Path) -> Result<Vec<std::fs::DirEntry>, LpmError> {
    let mut entries = std::fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    Ok(entries)
}

#[cfg(test)]
fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
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
    fn validate_directory_ignores_valid_materialized_skills_larger_than_the_authored_limit() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        std::fs::create_dir_all(&skills).unwrap();
        package::materialize(
            project.path(),
            "owner.package",
            Some("1.0.0"),
            &[lpm_registry::Skill {
                name: "consumer".into(),
                description: None,
                version: None,
                globs: Vec::new(),
                content: Some("x".repeat(MAX_SKILL_SIZE as usize + 1)),
                raw_content: None,
                size_bytes: None,
            }],
        )
        .unwrap();

        let report = validate_directory(&skills).unwrap();

        assert_eq!(report.ignored_package_sets, 1);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.validated_files.is_empty());
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
        assert!(report.validated_files.len() <= MAX_SKILL_COUNT);
    }

    #[test]
    fn validation_does_not_retain_skill_bytes_beyond_the_total_limit() {
        let project = tempfile::tempdir().unwrap();
        let skills = project.path().join(".lpm/skills");
        std::fs::create_dir_all(&skills).unwrap();
        for index in 0..MAX_SKILL_COUNT {
            let name = format!("skill-{index}");
            let mut content = valid_skill(&name);
            content.push_str(&"x".repeat(11 * 1024));
            std::fs::write(skills.join(format!("{name}.md")), content).unwrap();
        }

        let report = validate_directory(&skills).unwrap();
        let retained_bytes = report
            .validated_files
            .iter()
            .map(|skill| skill.content.len() as u64)
            .sum::<u64>();

        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("exceeds 100KB limit"))
        );
        assert!(retained_bytes <= MAX_TOTAL_SIZE, "{retained_bytes}");
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
