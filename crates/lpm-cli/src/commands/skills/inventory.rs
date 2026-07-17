use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use lpm_common::LpmError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::managed;
use super::package::{self, PackageManifestStatus};

const SCHEMA_VERSION: u32 = 1;
const MAX_SCANNED_SKILL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum SkillInventoryKind {
    Package,
    Managed,
    External,
}

impl SkillInventoryKind {
    fn slug(self) -> &'static str {
        match self {
            Self::Package => "package",
            Self::Managed => "managed",
            Self::External => "external",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum DashboardAction {
    Enable,
    Disable,
    Update,
    Remove,
}

impl DashboardAction {
    pub(super) fn slug(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Update => "update",
            Self::Remove => "remove",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SecurityFinding {
    pub(super) rule_id: String,
    pub(super) category: String,
    pub(super) severity: lpm_security::skill_security::SkillSecuritySeverity,
    pub(super) path: String,
    pub(super) line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SecurityAssessment {
    pub(super) status: String,
    pub(super) warning_count: usize,
    pub(super) block_count: usize,
    pub(super) findings: Vec<SecurityFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) message: Option<String>,
}

impl SecurityAssessment {
    pub(super) fn scanned(findings: Vec<SecurityFinding>) -> Self {
        let warning_count = findings
            .iter()
            .filter(|finding| {
                finding.severity == lpm_security::skill_security::SkillSecuritySeverity::Warning
            })
            .count();
        let block_count = findings.len() - warning_count;
        Self {
            status: "scanned".into(),
            warning_count,
            block_count,
            findings,
            message: None,
        }
    }

    pub(super) fn unavailable(message: String) -> Self {
        Self {
            status: "unavailable".into(),
            warning_count: 0,
            block_count: 0,
            findings: Vec::new(),
            message: Some(message),
        }
    }

    pub(super) fn needs_attention(&self) -> bool {
        self.status != "scanned" || self.warning_count > 0 || self.block_count > 0
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SkillTarget {
    pub(super) agent: String,
    pub(super) label: String,
    pub(super) path: String,
    pub(super) enabled: bool,
    pub(super) healthy: bool,
    pub(super) status: String,
    pub(super) materialization: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct SkillInventoryItem {
    pub(super) id: String,
    pub(super) kind: SkillInventoryKind,
    pub(super) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<String>,
    pub(super) source: String,
    pub(super) scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) context_tokens: Option<usize>,
    pub(super) targets: Vec<SkillTarget>,
    pub(super) healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) integrity: Option<String>,
    pub(super) security: SecurityAssessment,
    pub(super) actions: Vec<DashboardAction>,
    pub(super) command: String,
}

impl SkillInventoryItem {
    pub(super) fn needs_attention(&self) -> bool {
        !self.healthy || self.security.needs_attention()
    }
}

#[derive(Debug, Serialize)]
pub(super) struct InventoryCounts {
    total: usize,
    package: usize,
    managed: usize,
    external: usize,
    disabled: usize,
    needs_attention: usize,
    security_warnings: usize,
    security_blocks: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct AgentContextSummary {
    agent: String,
    label: String,
    enabled_skills: usize,
    estimated_context_tokens: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct InventorySnapshot {
    pub(super) success: bool,
    pub(super) schema_version: u32,
    pub(super) project: String,
    pub(super) includes_global: bool,
    pub(super) read_only: bool,
    pub(super) counts: InventoryCounts,
    pub(super) context_by_agent: Vec<AgentContextSummary>,
    pub(super) skills: Vec<SkillInventoryItem>,
}

pub(super) fn collect(
    project_dir: &Path,
    include_global: bool,
    read_only: bool,
) -> Result<InventorySnapshot, LpmError> {
    let mut skills = package_inventory(project_dir)?;
    skills.extend(managed::dashboard_inventory(project_dir, include_global)?);
    skills.sort_by(|left, right| {
        left.kind
            .slug()
            .cmp(right.kind.slug())
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.scope.cmp(&right.scope))
    });
    if read_only {
        for skill in &mut skills {
            skill.actions.clear();
        }
    }
    let counts = inventory_counts(&skills);
    let context_by_agent = context_by_agent(&skills);
    Ok(InventorySnapshot {
        success: true,
        schema_version: SCHEMA_VERSION,
        project: project_dir.display().to_string(),
        includes_global: include_global,
        read_only,
        counts,
        context_by_agent,
        skills,
    })
}

fn inventory_counts(skills: &[SkillInventoryItem]) -> InventoryCounts {
    InventoryCounts {
        total: skills.len(),
        package: skills
            .iter()
            .filter(|skill| skill.kind == SkillInventoryKind::Package)
            .count(),
        managed: skills
            .iter()
            .filter(|skill| skill.kind == SkillInventoryKind::Managed)
            .count(),
        external: skills
            .iter()
            .filter(|skill| skill.kind == SkillInventoryKind::External)
            .count(),
        disabled: skills
            .iter()
            .filter(|skill| {
                skill.kind == SkillInventoryKind::Managed
                    && !skill.targets.is_empty()
                    && skill.targets.iter().all(|target| !target.enabled)
            })
            .count(),
        needs_attention: skills
            .iter()
            .filter(|skill| skill.needs_attention())
            .count(),
        security_warnings: skills
            .iter()
            .map(|skill| skill.security.warning_count)
            .sum(),
        security_blocks: skills.iter().map(|skill| skill.security.block_count).sum(),
    }
}

fn context_by_agent(skills: &[SkillInventoryItem]) -> Vec<AgentContextSummary> {
    let mut summaries: BTreeMap<&str, AgentContextSummary> = BTreeMap::new();
    for skill in skills {
        let tokens = skill.context_tokens.unwrap_or(0);
        for target in skill.targets.iter().filter(|target| target.enabled) {
            let summary = summaries
                .entry(&target.agent)
                .or_insert_with(|| AgentContextSummary {
                    agent: target.agent.clone(),
                    label: target.label.clone(),
                    enabled_skills: 0,
                    estimated_context_tokens: 0,
                });
            summary.enabled_skills += 1;
            summary.estimated_context_tokens += tokens;
        }
    }
    summaries.into_values().collect()
}

fn package_inventory(project_dir: &Path) -> Result<Vec<SkillInventoryItem>, LpmError> {
    let skills_root = project_dir.join(".lpm").join("skills");
    let entries = match std::fs::read_dir(&skills_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    let mut result = Vec::new();
    for entry in entries {
        let entry = entry?;
        let directory = entry.path();
        let metadata = std::fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let package_name = entry.file_name().to_string_lossy().to_string();
        let manifest = package::read_manifest(&directory, &package_name);
        let mut observed = BTreeSet::new();
        for skill_entry in std::fs::read_dir(&directory)? {
            let skill_entry = skill_entry?;
            let path = skill_entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || path.extension().is_none_or(|extension| extension != "md")
            {
                continue;
            }
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            observed.insert(name.clone());
            let (content, security) = read_and_scan(&path);
            let description = content.as_deref().and_then(|content| {
                lpm_security::skill_security::parse_skill_frontmatter(content)
                    .0
                    .description
            });
            let context_tokens = content
                .as_deref()
                .map(|content| content.chars().count().div_ceil(4));
            let integrity = package_integrity(&manifest, &name, content.as_deref());
            let package = format!("@lpm.dev/{package_name}");
            let identity = format!("{}:{}", directory.display(), name);
            result.push(SkillInventoryItem {
                id: stable_id("package", &identity),
                kind: SkillInventoryKind::Package,
                name: name.clone(),
                description,
                source: package.clone(),
                scope: "project".into(),
                package: Some(package.clone()),
                version: package_version(&manifest),
                path: Some(path.display().to_string()),
                size_bytes: Some(metadata.len()),
                context_tokens,
                targets: Vec::new(),
                healthy: integrity != "modified" && integrity != "invalid-manifest",
                integrity: Some(integrity.into()),
                security,
                actions: Vec::new(),
                command: format!("lpm skills view {package_name}/{name}"),
            });
        }
        if let PackageManifestStatus::Valid(manifest) = &manifest {
            for name in manifest
                .skills
                .keys()
                .filter(|name| !observed.contains(*name))
            {
                let path = directory.join(format!("{name}.md"));
                let package = format!("@lpm.dev/{package_name}");
                let identity = format!("{}:{name}", directory.display());
                result.push(SkillInventoryItem {
                    id: stable_id("package", &identity),
                    kind: SkillInventoryKind::Package,
                    name: name.clone(),
                    description: None,
                    source: package.clone(),
                    scope: "project".into(),
                    package: Some(package),
                    version: manifest.version.clone(),
                    path: Some(path.display().to_string()),
                    size_bytes: None,
                    context_tokens: None,
                    targets: Vec::new(),
                    healthy: false,
                    integrity: Some("missing".into()),
                    security: SecurityAssessment::unavailable(
                        "package skill content is missing".into(),
                    ),
                    actions: Vec::new(),
                    command: format!("lpm skills view {package_name}/{name}"),
                });
            }
        }
    }
    Ok(result)
}

fn package_version(manifest: &PackageManifestStatus) -> Option<String> {
    match manifest {
        PackageManifestStatus::Valid(manifest) => manifest.version.clone(),
        PackageManifestStatus::Missing | PackageManifestStatus::Invalid => None,
    }
}

fn package_integrity(
    manifest: &PackageManifestStatus,
    skill_name: &str,
    content: Option<&str>,
) -> &'static str {
    let manifest = match manifest {
        PackageManifestStatus::Missing => return "untracked",
        PackageManifestStatus::Invalid => return "invalid-manifest",
        PackageManifestStatus::Valid(manifest) => manifest,
    };
    let Some(expected) = manifest.skills.get(skill_name) else {
        return "invalid-manifest";
    };
    let Some(content) = content else {
        return "unavailable";
    };
    if package::digest(content.as_bytes()) == *expected {
        "verified"
    } else {
        "modified"
    }
}

pub(super) fn read_and_scan(path: &Path) -> (Option<String>, SecurityAssessment) {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return (
                None,
                SecurityAssessment::unavailable(format!(
                    "could not inspect skill content: {}",
                    error.kind()
                )),
            );
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return (
            None,
            SecurityAssessment::unavailable("skill content is not a regular file".into()),
        );
    }
    if metadata.len() > MAX_SCANNED_SKILL_BYTES {
        return (
            None,
            SecurityAssessment::unavailable(format!(
                "skill content exceeds the {} byte dashboard scan limit",
                MAX_SCANNED_SKILL_BYTES
            )),
        );
    }
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            return (
                None,
                SecurityAssessment::unavailable(format!(
                    "could not read skill content: {}",
                    error.kind()
                )),
            );
        }
    };
    let display = path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into(),
    );
    let findings = lpm_security::skill_security::scan_skill_content(&content)
        .into_iter()
        .map(|finding| SecurityFinding {
            rule_id: finding.rule_id,
            category: finding.category,
            severity: finding.severity,
            path: display.clone(),
            line: finding.line_number,
        })
        .collect();
    (content.into(), SecurityAssessment::scanned(findings))
}

pub(super) fn read_and_scan_directory(
    directory: &Path,
) -> (Option<String>, Option<usize>, SecurityAssessment) {
    let files = match super::source::read_bounded_skill_directory(directory) {
        Ok(files) => files,
        Err(error) => {
            return (
                None,
                None,
                SecurityAssessment::unavailable(format!("could not scan skill directory: {error}")),
            );
        }
    };
    let mut skill_content = None;
    let mut context_chars = 0usize;
    let mut findings = Vec::new();
    for (path, bytes) in files {
        let is_primary = path == Path::new("SKILL.md");
        let content = match String::from_utf8(bytes) {
            Ok(content) => content,
            Err(_) if is_primary => {
                return (
                    None,
                    None,
                    SecurityAssessment::unavailable(
                        "primary SKILL.md is not valid UTF-8 text".into(),
                    ),
                );
            }
            Err(_) => continue,
        };
        context_chars = context_chars.saturating_add(content.chars().count());
        findings.extend(
            lpm_security::skill_security::scan_skill_content(&content)
                .into_iter()
                .map(|finding| SecurityFinding {
                    rule_id: finding.rule_id,
                    category: finding.category,
                    severity: finding.severity,
                    path: path.display().to_string(),
                    line: finding.line_number,
                }),
        );
        if is_primary {
            skill_content = Some(content);
        }
    }
    let Some(skill_content) = skill_content else {
        return (
            None,
            None,
            SecurityAssessment::unavailable("primary SKILL.md is missing".into()),
        );
    };
    (
        Some(skill_content),
        Some(context_chars.div_ceil(4)),
        SecurityAssessment::scanned(findings),
    )
}

pub(super) fn stable_id(kind: &str, identity: &str) -> String {
    let digest = Sha256::digest(identity.as_bytes());
    format!("{kind}:{}", hex::encode(digest))
}

pub(super) fn target_path(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_id_distinguishes_skill_kinds_with_the_same_identity() {
        assert_ne!(stable_id("managed", "same"), stable_id("external", "same"));
    }

    #[test]
    fn oversized_external_skill_is_not_read_or_scanned() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("SKILL.md");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_SCANNED_SKILL_BYTES + 1).unwrap();

        let (content, security) = read_and_scan(&path);

        assert!(content.is_none());
        assert_eq!(security.status, "unavailable");
    }

    #[test]
    fn package_inventory_verifies_materialized_manifest_digest() {
        let project = tempfile::tempdir().unwrap();
        package::materialize(
            project.path(),
            "owner.package",
            Some("1.2.3"),
            &[lpm_registry::Skill {
                name: "guide".into(),
                description: None,
                globs: Vec::new(),
                content: Some(
                    "---\nname: guide\ndescription: A useful package guide\n---\nUse the guide."
                        .into(),
                ),
                raw_content: None,
                size_bytes: None,
            }],
        )
        .unwrap();

        let inventory = collect(project.path(), false, true).unwrap();

        assert_eq!(inventory.skills[0].integrity.as_deref(), Some("verified"));
    }

    #[test]
    fn package_inventory_flags_a_malformed_integrity_manifest() {
        let project = tempfile::tempdir().unwrap();
        let directory = project.path().join(".lpm/skills/owner.package");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("guide.md"),
            "---\nname: guide\ndescription: A useful package guide\n---\nUse the guide.",
        )
        .unwrap();
        std::fs::write(directory.join(package::MANIFEST_FILE), "not json").unwrap();

        let inventory = collect(project.path(), false, true).unwrap();

        assert_eq!(
            inventory.skills[0].integrity.as_deref(),
            Some("invalid-manifest")
        );
    }

    #[test]
    fn package_inventory_surfaces_a_missing_manifest_skill_as_needing_attention() {
        let project = tempfile::tempdir().unwrap();
        package::materialize(
            project.path(),
            "owner.package",
            Some("1.2.3"),
            &[
                lpm_registry::Skill {
                    name: "available".into(),
                    description: None,
                    globs: Vec::new(),
                    content: Some(
                        "---\nname: available\ndescription: Available guide\n---\nUse it.".into(),
                    ),
                    raw_content: None,
                    size_bytes: None,
                },
                lpm_registry::Skill {
                    name: "missing".into(),
                    description: None,
                    globs: Vec::new(),
                    content: Some(
                        "---\nname: missing\ndescription: Missing guide\n---\nUse it.".into(),
                    ),
                    raw_content: None,
                    size_bytes: None,
                },
            ],
        )
        .unwrap();
        std::fs::remove_file(project.path().join(".lpm/skills/owner.package/missing.md")).unwrap();

        let inventory = collect(project.path(), false, true).unwrap();
        let missing = inventory
            .skills
            .iter()
            .find(|skill| skill.name == "missing")
            .expect("the missing manifest skill must remain visible");

        assert_eq!(missing.integrity.as_deref(), Some("missing"));
        assert!(!missing.healthy);
        assert_eq!(inventory.counts.needs_attention, 1);
    }
}
