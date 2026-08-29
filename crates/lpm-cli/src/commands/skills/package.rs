use lpm_common::{LpmError, PackageName};
use lpm_registry::Skill;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(super) const MANIFEST_FILE: &str = ".lpm-package-skills.json";
pub(super) const MANIFEST_VERSION: u32 = 1;
pub(super) const MAX_MANIFEST_SIZE: u64 = 64 * 1024;
const MAX_MATERIALIZED_SKILL_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PackageSkillsManifest {
    pub(super) schema_version: u32,
    pub(super) package: String,
    pub(super) version: Option<String>,
    pub(super) skills: BTreeMap<String, String>,
}

pub(super) enum PackageManifestStatus {
    Missing,
    Invalid,
    Valid(PackageSkillsManifest),
}

pub(crate) struct PackageSkillsResult {
    pub installed: usize,
    pub directory: PathBuf,
}

pub(crate) fn materialize(
    project_dir: &Path,
    package: &str,
    version: Option<&str>,
    skills: &[Skill],
) -> Result<PackageSkillsResult, LpmError> {
    let _lock = acquire_mutation_lock(project_dir)?;
    let parsed = PackageName::parse(package)?;
    let package = parsed.short();
    let entries = validated_entries(skills)?;
    let root = project_dir.join(".lpm").join("skills");
    super::path_security::ensure_contained_directory(project_dir, &root, "package skill storage")?;
    let target = root.join(&package);
    let had_previous = match std::fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(LpmError::Registry(format!(
                "refusing to replace package skill path that is not a regular directory: {}",
                target.display()
            )));
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(LpmError::Io(error)),
    };

    let staging = tempfile::Builder::new()
        .prefix(".package-skills-stage-")
        .tempdir_in(&root)
        .map_err(LpmError::Io)?;
    let mut manifest_skills = BTreeMap::new();
    for entry in &entries {
        std::fs::write(
            staging.path().join(format!("{}.md", entry.name)),
            entry.content.as_bytes(),
        )?;
        manifest_skills.insert(entry.name.to_string(), digest(entry.content.as_bytes()));
    }
    let manifest = PackageSkillsManifest {
        schema_version: MANIFEST_VERSION,
        package,
        version: version.map(str::to_string),
        skills: manifest_skills,
    };
    let mut manifest_content = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        LpmError::Registry(format!(
            "failed to serialize package skill manifest: {error}"
        ))
    })?;
    manifest_content.push(b'\n');
    std::fs::write(staging.path().join(MANIFEST_FILE), manifest_content)?;

    let backup_root = tempfile::Builder::new()
        .prefix(".package-skills-backup-")
        .tempdir_in(&root)
        .map_err(LpmError::Io)?;
    let backup = backup_root.path().join("previous");
    if had_previous {
        std::fs::rename(&target, &backup)?;
    }
    let staging_path = staging.keep();
    if let Err(error) = std::fs::rename(&staging_path, &target) {
        if had_previous {
            let _ = std::fs::rename(&backup, &target);
        }
        let _ = std::fs::remove_dir_all(&staging_path);
        return Err(LpmError::Io(error));
    }

    Ok(PackageSkillsResult {
        installed: entries.len(),
        directory: target,
    })
}

pub(crate) fn validate(skills: &[Skill]) -> Result<(), LpmError> {
    validated_entries(skills).map(|_| ())
}

pub(crate) fn remove(project_dir: &Path, package: &str) -> Result<u64, LpmError> {
    let _lock = acquire_mutation_lock(project_dir)?;
    let package = PackageName::parse(package)?.short();
    let root = project_dir.join(".lpm").join("skills");
    super::path_security::ensure_contained_directory(project_dir, &root, "package skill storage")?;
    let directory = root.join(package);
    let metadata = match std::fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(LpmError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LpmError::Registry(format!(
            "refusing to remove package skill path that is not a regular directory: {}",
            directory.display()
        )));
    }
    let bytes = crate::commands::cache::dir_size(&directory).unwrap_or(0);
    std::fs::remove_dir_all(directory)?;
    Ok(bytes)
}

pub(super) fn read_manifest(directory: &Path, expected_package: &str) -> PackageManifestStatus {
    let path = directory.join(MANIFEST_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return PackageManifestStatus::Missing;
        }
        Err(_) => return PackageManifestStatus::Invalid,
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_MANIFEST_SIZE
    {
        return PackageManifestStatus::Invalid;
    }
    let content = match lpm_common::read_text_file_capped(&path, MAX_MANIFEST_SIZE) {
        Ok(content) => content,
        Err(_) => return PackageManifestStatus::Invalid,
    };
    let Ok(manifest) = serde_json::from_str::<PackageSkillsManifest>(&content) else {
        return PackageManifestStatus::Invalid;
    };
    if manifest.schema_version == MANIFEST_VERSION
        && manifest.package == expected_package
        && manifest
            .skills
            .keys()
            .all(|name| lpm_common::is_safe_skill_name(name))
    {
        PackageManifestStatus::Valid(manifest)
    } else {
        PackageManifestStatus::Invalid
    }
}

pub(crate) fn is_materialized_directory(directory: &Path) -> bool {
    materialized_skill_names(directory).is_some()
}

pub(crate) fn materialized_skill_names(directory: &Path) -> Option<Vec<String>> {
    let package = directory.file_name().and_then(|name| name.to_str())?;
    materialized_directory_manifest(directory, package)
        .map(|manifest| manifest.skills.into_keys().collect())
}

pub(crate) fn acquire_mutation_lock(
    project_dir: &Path,
) -> Result<lpm_common::ExclusiveLockHandle, LpmError> {
    super::path_security::ensure_contained_directory(
        project_dir,
        &project_dir.join(".lpm"),
        "package skill state",
    )?;
    lpm_common::acquire_exclusive_lock(project_dir.join(".lpm/.package-skills.lock"))
}

pub(crate) fn materialization_complete(project_dir: &Path, package_json: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(package_json) else {
        return false;
    };
    let mut packages = BTreeSet::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(dependencies) = value.get(section).and_then(serde_json::Value::as_object) else {
            continue;
        };
        for name in dependencies
            .keys()
            .filter(|name| name.starts_with("@lpm.dev/"))
        {
            let Ok(name) = PackageName::parse(name) else {
                return false;
            };
            packages.insert(name.short());
        }
    }
    packages
        .iter()
        .all(|package| package_materialization_complete(project_dir, package))
}

fn package_materialization_complete(project_dir: &Path, package: &str) -> bool {
    let directory = project_dir.join(".lpm").join("skills").join(package);
    materialized_directory_manifest(&directory, package).is_some()
}

fn materialized_directory_manifest(
    directory: &Path,
    package: &str,
) -> Option<PackageSkillsManifest> {
    let Ok(metadata) = std::fs::symlink_metadata(directory) else {
        return None;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return None;
    }
    let PackageManifestStatus::Valid(manifest) = read_manifest(directory, package) else {
        return None;
    };
    let Ok(entries) = std::fs::read_dir(directory) else {
        return None;
    };
    let mut seen = BTreeSet::new();
    for entry in entries {
        let Ok(entry) = entry else {
            return None;
        };
        let name = entry.file_name();
        if name == MANIFEST_FILE {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            return None;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return None;
        }
        if path.extension().is_none_or(|extension| extension != "md") {
            return None;
        }
        let skill_name = path.file_stem().and_then(|name| name.to_str())?;
        let expected_digest = manifest.skills.get(skill_name)?;
        let Ok(content) = lpm_common::read_text_file_capped(&path, MAX_MATERIALIZED_SKILL_SIZE)
        else {
            return None;
        };
        if digest(content.as_bytes()) != *expected_digest {
            return None;
        }
        seen.insert(skill_name.to_string());
    }
    (seen.len() == manifest.skills.len()).then_some(manifest)
}

struct ValidatedEntry<'a> {
    name: &'a str,
    content: Cow<'a, str>,
}

fn validated_entries(skills: &[Skill]) -> Result<Vec<ValidatedEntry<'_>>, LpmError> {
    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(skills.len());
    for skill in skills {
        if !lpm_common::is_safe_skill_name(&skill.name) {
            return Err(LpmError::Registry(format!(
                "registry returned an unsafe package skill name: {}",
                skill.name
            )));
        }
        if !seen.insert(skill.name.as_str()) {
            return Err(LpmError::Registry(format!(
                "registry returned duplicate package skill name: {}",
                skill.name
            )));
        }
        let content = materialized_content(skill)?;
        entries.push(ValidatedEntry {
            name: skill.name.as_str(),
            content,
        });
    }
    Ok(entries)
}

fn materialized_content(skill: &Skill) -> Result<Cow<'_, str>, LpmError> {
    if let Some(raw_content) = skill
        .raw_content
        .as_deref()
        .filter(|content| !content.is_empty())
    {
        return Ok(Cow::Borrowed(raw_content));
    }

    let content = skill
        .content
        .as_deref()
        .filter(|content| !content.is_empty())
        .ok_or_else(|| {
            LpmError::Registry(format!(
                "registry returned package skill `{}` without content",
                skill.name
            ))
        })?;
    if content.starts_with("---\n") || content.starts_with("---\r\n") {
        return Ok(Cow::Borrowed(content));
    }
    let Some(description) = skill.description.as_deref() else {
        return Ok(Cow::Borrowed(content));
    };

    let mut document = String::with_capacity(content.len() + description.len() + 128);
    document.push_str("---\nname: ");
    push_yaml_string(&mut document, &skill.name)?;
    document.push_str("\ndescription: ");
    push_yaml_string(&mut document, description)?;
    if let Some(version) = skill
        .version
        .as_deref()
        .filter(|version| !version.is_empty())
    {
        document.push_str("\nversion: ");
        push_yaml_string(&mut document, version)?;
    }
    if !skill.globs.is_empty() {
        document.push_str("\nglobs:");
        for glob in &skill.globs {
            document.push_str("\n  - ");
            push_yaml_string(&mut document, glob)?;
        }
    }
    document.push_str("\n---\n");
    document.push_str(content);
    Ok(Cow::Owned(document))
}

fn push_yaml_string(output: &mut String, value: &str) -> Result<(), LpmError> {
    let encoded = serde_json::to_string(value).map_err(|error| {
        LpmError::Registry(format!(
            "failed to encode package skill frontmatter: {error}"
        ))
    })?;
    output.push_str(&encoded);
    Ok(())
}

pub(super) fn digest(content: &[u8]) -> String {
    format!("{:x}", Sha256::digest(content))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skill(name: &str, content: &str) -> Skill {
        Skill {
            name: name.to_string(),
            description: None,
            version: None,
            globs: Vec::new(),
            content: Some(content.to_string()),
            raw_content: None,
            size_bytes: None,
        }
    }

    #[test]
    fn materialize_rejects_registry_path_traversal_before_writing() {
        let project = tempfile::tempdir().unwrap();
        let skills = vec![skill("../../escape", "bad")];

        let error = materialize(project.path(), "owner.package", Some("1.0.0"), &skills)
            .err()
            .expect("unsafe registry skill name must fail");

        assert!(error.to_string().contains("unsafe package skill name"));
        assert!(!project.path().join("escape.md").exists());
    }

    #[cfg(unix)]
    #[test]
    fn materialize_rejects_symlinked_skills_parent_without_external_write() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join(".lpm/skills")).unwrap();

        let error = materialize(
            project.path(),
            "owner.package",
            Some("1.0.0"),
            &[skill("guide", "content")],
        )
        .err()
        .expect("symlinked parent must be rejected");

        assert!(error.to_string().contains("symlink"));
        assert!(!outside.path().join("owner.package").exists());
    }

    #[cfg(unix)]
    #[test]
    fn remove_rejects_symlinked_skills_parent_without_external_deletion() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let package = outside.path().join("owner.package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("guide.md"), "content").unwrap();
        std::fs::create_dir(project.path().join(".lpm")).unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join(".lpm/skills")).unwrap();

        let error =
            remove(project.path(), "owner.package").expect_err("symlinked parent must be rejected");

        assert!(error.to_string().contains("symlink"));
        assert!(package.join("guide.md").is_file());
    }

    #[test]
    fn materialize_reconciles_removed_package_skills() {
        let project = tempfile::tempdir().unwrap();
        materialize(
            project.path(),
            "owner.package",
            Some("1.0.0"),
            &[skill("old", "old"), skill("kept", "before")],
        )
        .unwrap();

        materialize(
            project.path(),
            "owner.package",
            Some("2.0.0"),
            &[skill("kept", "after")],
        )
        .unwrap();

        let directory = project.path().join(".lpm/skills/owner.package");
        assert!(!directory.join("old.md").exists());
        assert_eq!(
            std::fs::read_to_string(directory.join("kept.md")).unwrap(),
            "after"
        );
    }

    #[test]
    fn materialize_reconstructs_redacted_frontmatter_with_the_authored_version() {
        let project = tempfile::tempdir().unwrap();
        let skill: Skill = serde_json::from_value(serde_json::json!({
            "name": "guide",
            "description": "Guidance written for an earlier package release",
            "version": "0.8.0",
            "globs": ["**/*.rs"],
            "content": "# Guide\n\nUse the supported API."
        }))
        .unwrap();

        materialize(project.path(), "owner.package", Some("1.0.0"), &[skill]).unwrap();

        let content =
            std::fs::read_to_string(project.path().join(".lpm/skills/owner.package/guide.md"))
                .unwrap();
        let (meta, body, errors) =
            lpm_security::skill_security::parse_agent_skill_frontmatter(&content);
        assert!(errors.is_empty(), "reconstructed frontmatter: {errors:?}");
        assert_eq!(meta.version.as_deref(), Some("0.8.0"));
        assert_eq!(meta.globs, ["**/*.rs"]);
        assert!(body.contains("Use the supported API."));
    }

    #[test]
    fn materialization_complete_detects_missing_skill_content() {
        let project = tempfile::tempdir().unwrap();
        materialize(
            project.path(),
            "owner.package",
            Some("1.0.0"),
            &[skill("guide", "content")],
        )
        .unwrap();
        std::fs::remove_file(project.path().join(".lpm/skills/owner.package/guide.md")).unwrap();
        let package_json = r#"{"dependencies":{"@lpm.dev/owner.package":"1.0.0"}}"#;

        assert!(!materialization_complete(project.path(), package_json));
    }

    #[test]
    fn read_manifest_rejects_oversized_ownership_files() {
        let project = tempfile::tempdir().unwrap();
        let directory = project.path().join("owner.package");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join(MANIFEST_FILE),
            vec![b' '; MAX_MANIFEST_SIZE as usize + 1],
        )
        .unwrap();

        assert!(matches!(
            read_manifest(&directory, "owner.package"),
            PackageManifestStatus::Invalid
        ));
    }

    #[cfg(unix)]
    #[test]
    fn read_manifest_rejects_symlinked_ownership_files() {
        let project = tempfile::tempdir().unwrap();
        let directory = project.path().join("owner.package");
        let external = project.path().join("manifest.json");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            &external,
            r#"{"schema_version":1,"package":"owner.package","version":"1.0.0","skills":{}}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&external, directory.join(MANIFEST_FILE)).unwrap();

        assert!(matches!(
            read_manifest(&directory, "owner.package"),
            PackageManifestStatus::Invalid
        ));
    }

    #[test]
    fn remove_deletes_package_owned_skill_directory() {
        let project = tempfile::tempdir().unwrap();
        materialize(
            project.path(),
            "owner.package",
            Some("1.0.0"),
            &[skill("guide", "content")],
        )
        .unwrap();

        let removed = remove(project.path(), "@lpm.dev/owner.package").unwrap();

        assert!(removed > 0);
        assert!(!project.path().join(".lpm/skills/owner.package").exists());
    }
}
