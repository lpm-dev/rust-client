use crate::skills_model::{AgentTarget, ManagedSkill, SkillBinding, SkillManifest, SkillScope};
use lpm_common::LpmError;
use lpm_security::skill_security::parse_skill_frontmatter;
use std::path::Path;

const MAX_INVENTORY_SKILL_FILE_BYTES: u64 = 1024 * 1024;

pub(crate) fn load(
    scopes: &[SkillScope],
    project_dir: &Path,
) -> Result<Vec<ManagedSkill>, LpmError> {
    let mut skills = Vec::new();
    for scope in scopes {
        skills.extend(SkillManifest::load(*scope, project_dir)?.skills);
        discover_agent_skills(&mut skills, *scope, project_dir)?;
        if *scope == SkillScope::Project {
            discover_package_skills(&mut skills, project_dir)?;
        }
    }
    skills.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.source_kind.cmp(&right.source_kind))
            .then_with(|| left.source.cmp(&right.source))
    });
    Ok(skills)
}

fn discover_agent_skills(
    skills: &mut Vec<ManagedSkill>,
    scope: SkillScope,
    project_dir: &Path,
) -> Result<(), LpmError> {
    for agent in AgentTarget::ALL {
        for root in agent.inventory_roots(scope, project_dir)? {
            let entries = match std::fs::read_dir(&root) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(LpmError::Io(error)),
            };
            for entry in entries {
                let entry = entry.map_err(LpmError::Io)?;
                let skill_file = entry.path().join("SKILL.md");
                if !skill_file.is_file() {
                    continue;
                }
                let id = entry.file_name().to_string_lossy().to_string();
                if skills
                    .iter()
                    .any(|skill| skill.scope == scope && skill.id == id)
                {
                    continue;
                }
                let size_bytes = skill_file.metadata().map_err(LpmError::Io)?.len();
                let (name, description) = read_external_metadata(&skill_file, &id, size_bytes)?;
                if let Some(existing) = skills.iter_mut().find(|skill| {
                    skill.scope == scope
                        && skill.source_kind == "external"
                        && skill.name == name
                        && skill.id == id
                }) {
                    if !existing
                        .bindings
                        .iter()
                        .any(|binding| binding.agent == agent)
                    {
                        existing.bindings.push(SkillBinding {
                            agent,
                            enabled: true,
                            copied: false,
                        });
                    }
                    continue;
                }
                skills.push(ManagedSkill {
                    id,
                    name,
                    description,
                    source: skill_file.display().to_string(),
                    source_kind: "external".into(),
                    resolved_revision: None,
                    digest: String::new(),
                    scope,
                    bindings: vec![SkillBinding {
                        agent,
                        enabled: true,
                        copied: false,
                    }],
                    estimated_tokens: 0,
                    size_bytes,
                });
            }
        }
    }
    Ok(())
}

fn discover_package_skills(
    skills: &mut Vec<ManagedSkill>,
    project_dir: &Path,
) -> Result<(), LpmError> {
    let root = project_dir.join(".lpm").join("skills");
    let packages = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    for package in packages {
        let package = package.map_err(LpmError::Io)?;
        if !package.path().is_dir() {
            continue;
        }
        let package_name = package.file_name().to_string_lossy().to_string();
        for entry in std::fs::read_dir(package.path()).map_err(LpmError::Io)? {
            let entry = entry.map_err(LpmError::Io)?;
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "md") {
                continue;
            }
            let name = path
                .file_stem()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let id = format!("package--{package_name}--{name}");
            if skills.iter().any(|skill| skill.id == id) {
                continue;
            }
            let size_bytes = path.metadata().map_err(LpmError::Io)?.len();
            skills.push(ManagedSkill {
                id,
                name,
                description: format!("Package skill from @lpm.dev/{package_name}"),
                source: format!("@lpm.dev/{package_name}"),
                source_kind: "package".into(),
                resolved_revision: None,
                digest: String::new(),
                scope: SkillScope::Project,
                bindings: Vec::new(),
                estimated_tokens: 0,
                size_bytes,
            });
        }
    }
    Ok(())
}

fn read_external_metadata(
    skill_file: &Path,
    fallback_name: &str,
    size_bytes: u64,
) -> Result<(String, String), LpmError> {
    if size_bytes > MAX_INVENTORY_SKILL_FILE_BYTES {
        return Ok((fallback_name.to_string(), "External agent skill".into()));
    }
    let content = std::fs::read_to_string(skill_file).map_err(LpmError::Io)?;
    let (metadata, _, _) = parse_skill_frontmatter(&content);
    if let (Some(name), Some(description)) = (metadata.name, metadata.description) {
        return Ok((name, description));
    }
    Ok((fallback_name.to_string(), "External agent skill".into()))
}
