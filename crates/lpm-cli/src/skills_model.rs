use lpm_common::{LpmError, write_file_atomic};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SkillScope {
    Project,
    Global,
}

impl SkillScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Global => "global",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AgentTarget {
    Codex,
    ClaudeCode,
    Cursor,
}

impl AgentTarget {
    pub(crate) const ALL: [Self; 3] = [Self::Codex, Self::ClaudeCode, Self::Cursor];

    pub(crate) fn parse(value: &str) -> Result<Self, LpmError> {
        match value {
            "codex" => Ok(Self::Codex),
            "claude-code" | "claude" => Ok(Self::ClaudeCode),
            "cursor" => Ok(Self::Cursor),
            _ => Err(LpmError::Registry(format!(
                "unsupported agent `{value}`; supported agents: codex, claude-code, cursor"
            ))),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
        }
    }

    pub(crate) fn display_name(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::Cursor => "Cursor",
        }
    }

    pub(crate) fn skill_root(
        self,
        scope: SkillScope,
        project_dir: &Path,
    ) -> Result<PathBuf, LpmError> {
        match (self, scope) {
            (Self::Codex, SkillScope::Project) => Ok(project_dir.join(".agents").join("skills")),
            (Self::ClaudeCode, SkillScope::Project) => {
                Ok(project_dir.join(".claude").join("skills"))
            }
            (Self::Cursor, SkillScope::Project) => Ok(project_dir.join(".cursor").join("skills")),
            (Self::Codex, SkillScope::Global) => Ok(home_dir()?.join(".codex").join("skills")),
            (Self::ClaudeCode, SkillScope::Global) => {
                Ok(home_dir()?.join(".claude").join("skills"))
            }
            (Self::Cursor, SkillScope::Global) => Ok(home_dir()?.join(".cursor").join("skills")),
        }
    }

    pub(crate) fn inventory_roots(
        self,
        scope: SkillScope,
        project_dir: &Path,
    ) -> Result<Vec<PathBuf>, LpmError> {
        let primary = self.skill_root(scope, project_dir)?;
        if self == Self::Codex && scope == SkillScope::Global {
            return Ok(vec![home_dir()?.join(".agents").join("skills"), primary]);
        }
        Ok(vec![primary])
    }

    pub(crate) fn is_detected(self, scope: SkillScope, project_dir: &Path) -> bool {
        self.inventory_roots(scope, project_dir)
            .is_ok_and(|paths| paths.iter().any(|path| path.exists()))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct SkillBinding {
    pub(crate) agent: AgentTarget,
    pub(crate) enabled: bool,
    pub(crate) copied: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ManagedSkill {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) source: String,
    pub(crate) source_kind: String,
    pub(crate) resolved_revision: Option<String>,
    pub(crate) digest: String,
    pub(crate) scope: SkillScope,
    pub(crate) bindings: Vec<SkillBinding>,
    pub(crate) estimated_tokens: u64,
    pub(crate) size_bytes: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub(crate) struct SkillManifest {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) skills: Vec<ManagedSkill>,
}

impl SkillManifest {
    pub(crate) fn load(scope: SkillScope, project_dir: &Path) -> Result<Self, LpmError> {
        let path = manifest_path(scope, project_dir)?;
        if !path.exists() {
            return Ok(Self {
                version: MANIFEST_VERSION,
                skills: Vec::new(),
            });
        }

        let content = std::fs::read_to_string(&path).map_err(LpmError::Io)?;
        let manifest: Self = toml::from_str(&content).map_err(|error| {
            LpmError::Registry(format!(
                "invalid skills manifest {}: {error}",
                path.display()
            ))
        })?;
        if manifest.version != MANIFEST_VERSION {
            return Err(LpmError::Registry(format!(
                "unsupported skills manifest version {} in {}",
                manifest.version,
                path.display()
            )));
        }
        Ok(manifest)
    }

    pub(crate) fn save(&self, scope: SkillScope, project_dir: &Path) -> Result<(), LpmError> {
        let path = manifest_path(scope, project_dir)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(LpmError::Io)?;
        }
        let content = toml::to_string_pretty(self).map_err(|error| {
            LpmError::Registry(format!("failed to serialize skills manifest: {error}"))
        })?;
        write_file_atomic(&path, content).map_err(LpmError::Io)
    }
}

pub(crate) fn managed_root(scope: SkillScope, project_dir: &Path) -> Result<PathBuf, LpmError> {
    match scope {
        SkillScope::Project => Ok(project_dir.join(".lpm").join("agent-skills")),
        SkillScope::Global => Ok(home_dir()?.join(".lpm").join("agent-skills")),
    }
}

fn manifest_path(scope: SkillScope, project_dir: &Path) -> Result<PathBuf, LpmError> {
    match scope {
        SkillScope::Project => Ok(project_dir.join("lpm-skills.toml")),
        SkillScope::Global => Ok(home_dir()?.join(".lpm").join("skills.toml")),
    }
}

fn home_dir() -> Result<PathBuf, LpmError> {
    dirs::home_dir()
        .ok_or_else(|| LpmError::Registry("could not determine the home directory".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_target_rejects_unknown_name() {
        assert!(AgentTarget::parse("unknown-agent").is_err());
    }

    #[test]
    fn project_manifest_round_trips() {
        let project = tempfile::tempdir().unwrap();
        let manifest = SkillManifest {
            version: MANIFEST_VERSION,
            skills: vec![ManagedSkill {
                id: "source--find-skills".into(),
                name: "find-skills".into(),
                description: "Find skills".into(),
                source: "./skills".into(),
                source_kind: "local".into(),
                resolved_revision: None,
                digest: "abc".into(),
                scope: SkillScope::Project,
                bindings: vec![SkillBinding {
                    agent: AgentTarget::Codex,
                    enabled: true,
                    copied: false,
                }],
                estimated_tokens: 12,
                size_bytes: 48,
            }],
        };

        manifest.save(SkillScope::Project, project.path()).unwrap();
        let loaded = SkillManifest::load(SkillScope::Project, project.path()).unwrap();
        assert_eq!(loaded.skills.len(), 1);
        assert_eq!(loaded.skills[0].name, "find-skills");
    }
}
