use super::source::{self, DiscoveredSkill, SourceDescriptor, SourceTree};
use super::{AgentTarget, ManageArgs, PruneArgs};
use lpm_common::{LpmError, LpmRoot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

const STATE_VERSION: u32 = 1;
const STATE_FILE: &str = "skills.lock.json";
const COPY_MARKER: &str = ".lpm-managed-skill.json";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Project,
    Global,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Global => "global",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
    scope: Scope,
    project_dir: PathBuf,
}

impl Store {
    pub fn for_scope(scope: Scope, project_dir: &Path) -> Result<Self, LpmError> {
        let root = match scope {
            Scope::Project => project_dir.join(".lpm").join("managed-skills"),
            Scope::Global => LpmRoot::from_env()?.root().join("managed-skills"),
        };
        Ok(Self {
            root,
            scope,
            project_dir: project_dir.to_path_buf(),
        })
    }

    fn state_path(&self) -> PathBuf {
        self.root.join(STATE_FILE)
    }

    fn canonical_path(&self, source: &SourceDescriptor, skill: &DiscoveredSkill) -> PathBuf {
        self.root
            .join("sources")
            .join(short_hash(&source.stable_identity()))
            .join(&source.revision()[..16])
            .join(&skill.name)
    }

    fn relative_canonical_path(
        &self,
        source: &SourceDescriptor,
        skill: &DiscoveredSkill,
    ) -> String {
        self.canonical_path(source, skill)
            .strip_prefix(&self.root)
            .unwrap_or_else(|_| Path::new(""))
            .display()
            .to_string()
    }

    fn target_path(&self, agent: AgentTarget, name: &str) -> Result<PathBuf, LpmError> {
        let root = match self.scope {
            Scope::Project => match agent {
                AgentTarget::Codex => self.project_dir.join(".agents").join("skills"),
                AgentTarget::ClaudeCode => self.project_dir.join(".claude").join("skills"),
                AgentTarget::Cursor => self.project_dir.join(".cursor").join("skills"),
            },
            Scope::Global => global_agent_root(agent)?,
        };
        Ok(root.join(name))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannedChange {
    pub action: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct InstallPlan {
    pub changes: Vec<PlannedChange>,
    pending: Vec<PendingRecord>,
}

#[derive(Debug, Clone)]
struct PendingRecord {
    record: ManagedSkillRecord,
    targets: Vec<PlannedTarget>,
}

#[derive(Debug, Clone)]
struct PlannedTarget {
    agent: AgentTarget,
    path: PathBuf,
    materialization: Materialization,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Materialization {
    Link,
    Copy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ManagedState {
    #[serde(default = "state_version")]
    state_version: u32,
    #[serde(default)]
    skills: BTreeMap<String, ManagedSkillRecord>,
}

fn state_version() -> u32 {
    STATE_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedSkillRecord {
    name: String,
    description: String,
    source: SourceDescriptor,
    canonical_dir: String,
    context_tokens: usize,
    #[serde(default)]
    targets: BTreeMap<AgentTarget, TargetRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TargetRecord {
    id: String,
    path: String,
    materialization: Materialization,
    enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedInventory {
    pub name: String,
    pub description: String,
    pub source: String,
    pub scope: String,
    pub context_tokens: usize,
    pub agents: Vec<AgentTarget>,
    pub healthy: bool,
}

impl ManagedInventory {
    pub fn summary(&self) -> String {
        format!(
            "{} · ~{} tokens · {}",
            self.source,
            self.context_tokens,
            if self.healthy {
                "healthy"
            } else {
                "needs attention"
            }
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalInventory {
    pub name: String,
    pub path: String,
    pub agent: AgentTarget,
    pub scope: String,
}

impl ExternalInventory {
    pub fn summary(&self) -> String {
        format!("{} · {}", self.scope, self.path)
    }
}

pub fn plan_install(
    store: &Store,
    tree: &SourceTree,
    skills: &[&DiscoveredSkill],
    agents: &[AgentTarget],
    copy: bool,
) -> Result<InstallPlan, LpmError> {
    let state = load_state(store)?;
    let materialization = if copy {
        Materialization::Copy
    } else {
        Materialization::Link
    };
    let mut changes = Vec::with_capacity(skills.len() * (agents.len() + 1));
    let mut pending = Vec::with_capacity(skills.len());
    for skill in skills {
        let existing = state.skills.get(&skill.name);
        if let Some(existing) = existing
            && existing.source.stable_identity() != tree.descriptor.stable_identity()
        {
            return Err(LpmError::Registry(format!(
                "managed skill name `{}` already belongs to {}; remove it before adding a different source",
                skill.name,
                existing.source.display()
            )));
        }
        let canonical = store.canonical_path(&tree.descriptor, skill);
        if canonical.exists() {
            changes.push(PlannedChange {
                action: "reuse managed content".into(),
                path: canonical.clone(),
            });
        } else {
            changes.push(PlannedChange {
                action: "write managed content".into(),
                path: canonical.clone(),
            });
        }
        let requested_agents: BTreeSet<_> = agents.iter().copied().collect();
        let existing_canonical = existing.map_or_else(
            || canonical.clone(),
            |record| store.root.join(&record.canonical_dir),
        );
        let existing_agents: BTreeSet<_> = existing
            .map(|record| record.targets.keys().copied().collect())
            .unwrap_or_default();
        let mut target_records =
            existing.map_or_else(BTreeMap::new, |record| record.targets.clone());
        for agent in requested_agents.iter().copied() {
            let target = store.target_path(agent, &skill.name)?;
            target_records.insert(
                agent,
                TargetRecord {
                    id: skill.name.clone(),
                    path: target.display().to_string(),
                    materialization,
                    enabled: true,
                },
            );
        }

        let mut targets = Vec::with_capacity(target_records.len());
        for (agent, target_record) in &target_records {
            if !target_record.enabled {
                continue;
            }
            let target = PathBuf::from(&target_record.path);
            if target.symlink_metadata().is_ok()
                && (!existing_agents.contains(agent)
                    || !target_is_owned(&target, target_record, &existing_canonical))
            {
                return Err(LpmError::Registry(format!(
                    "refusing to replace an external skill target: {}",
                    target.display()
                )));
            }
            changes.push(PlannedChange {
                action: if requested_agents.contains(agent) {
                    match target_record.materialization {
                        Materialization::Link => "link agent skill".into(),
                        Materialization::Copy => "copy agent skill".into(),
                    }
                } else {
                    "refresh managed agent skill".into()
                },
                path: target.clone(),
            });
            targets.push(PlannedTarget {
                agent: *agent,
                path: target,
                materialization: target_record.materialization,
            });
        }
        pending.push(PendingRecord {
            record: ManagedSkillRecord {
                name: skill.name.clone(),
                description: skill.description.clone(),
                source: tree.descriptor.clone(),
                canonical_dir: store.relative_canonical_path(&tree.descriptor, skill),
                context_tokens: skill.context_tokens,
                targets: target_records,
            },
            targets,
        });
    }
    Ok(InstallPlan { changes, pending })
}

pub fn apply_install(
    store: &Store,
    tree: &SourceTree,
    skills: &[&DiscoveredSkill],
    plan: InstallPlan,
) -> Result<(), LpmError> {
    if skills.len() != plan.pending.len() {
        return Err(LpmError::Registry(
            "managed skill install plan no longer matches selected skills".into(),
        ));
    }
    let mut state = load_state(store)?;
    for (skill, pending) in skills.iter().zip(plan.pending) {
        let canonical = store.canonical_path(&tree.descriptor, skill);
        if !canonical.exists() {
            write_canonical_skill(store, tree, skill, &canonical)?;
        }
        let previous = state.skills.get(&skill.name).cloned();
        let mut record = pending.record;
        for target in pending.targets {
            if let Some(previous) = previous.as_ref()
                && let Some(previous_target) = previous.targets.get(&target.agent)
            {
                remove_owned_target(
                    &target.path,
                    previous_target,
                    store.root.join(&previous.canonical_dir),
                    &previous.name,
                )?;
            }
            let actual_method = materialize_target(
                &canonical,
                &target.path,
                target.materialization,
                &record.name,
            )?;
            if let Some(target_record) = record.targets.get_mut(&target.agent) {
                target_record.materialization = actual_method;
            }
        }
        if let Some(previous) = previous {
            let previous_canonical = store.root.join(&previous.canonical_dir);
            if previous_canonical != canonical && previous_canonical.is_dir() {
                std::fs::remove_dir_all(previous_canonical)?;
            }
        }
        state.skills.insert(record.name.clone(), record);
    }
    write_state(store, &state)
}

fn write_canonical_skill(
    store: &Store,
    tree: &SourceTree,
    skill: &DiscoveredSkill,
    canonical: &Path,
) -> Result<(), LpmError> {
    let parent = canonical.parent().ok_or_else(|| {
        LpmError::Registry("managed canonical skill path has no parent directory".into())
    })?;
    std::fs::create_dir_all(parent)?;
    let staging = tempfile::Builder::new()
        .prefix(".lpm-skill-")
        .tempdir_in(parent)
        .map_err(LpmError::Io)?;
    for (path, content) in tree.files.range(skill.directory.clone()..) {
        if !path.starts_with(&skill.directory) {
            break;
        }
        let relative = path.strip_prefix(&skill.directory).map_err(|_| {
            LpmError::Registry("selected skill file escaped its source directory".into())
        })?;
        if relative.as_os_str().is_empty() || !safe_relative_path(relative) {
            return Err(LpmError::Registry(
                "selected skill contains an unsafe relative path".into(),
            ));
        }
        let destination = staging.path().join(relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(destination, content)?;
    }
    let staging_path = staging.keep();
    if canonical.exists() {
        std::fs::remove_dir_all(canonical)?;
    }
    std::fs::rename(staging_path, canonical)?;
    let _ = store;
    Ok(())
}

fn materialize_target(
    canonical: &Path,
    target: &Path,
    requested: Materialization,
    identifier: &str,
) -> Result<Materialization, LpmError> {
    let parent = target
        .parent()
        .ok_or_else(|| LpmError::Registry("agent target path has no parent directory".into()))?;
    std::fs::create_dir_all(parent)?;
    if requested == Materialization::Link {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(canonical, target)?;
            return Ok(Materialization::Link);
        }
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_dir(canonical, target).is_ok() {
                return Ok(Materialization::Link);
            }
        }
    }
    copy_directory(canonical, target)?;
    std::fs::write(
        target.join(COPY_MARKER),
        serde_json::to_string(&serde_json::json!({"id": identifier})).unwrap(),
    )?;
    Ok(Materialization::Copy)
}

fn copy_directory(source: &Path, destination: &Path) -> Result<(), LpmError> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(LpmError::Registry(format!(
                "refusing unexpected symlink in managed source: {}",
                entry.path().display()
            )));
        }
        let destination_path = destination.join(entry.file_name());
        if metadata.is_dir() {
            copy_directory(&entry.path(), &destination_path)?;
        } else if metadata.is_file() {
            std::fs::copy(entry.path(), destination_path)?;
        }
    }
    Ok(())
}

fn target_is_owned(target: &Path, record: &TargetRecord, canonical: &Path) -> bool {
    match record.materialization {
        Materialization::Link => std::fs::read_link(target).is_ok_and(|path| path == canonical),
        Materialization::Copy => copy_marker_matches(target, &record.id),
    }
}

fn copy_marker_matches(target: &Path, expected: &str) -> bool {
    std::fs::read_to_string(target.join(COPY_MARKER)).is_ok_and(|content| {
        serde_json::from_str::<serde_json::Value>(&content)
            .ok()
            .and_then(|value| {
                value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .is_some_and(|identifier| identifier == expected)
    })
}

fn remove_owned_target(
    target: &Path,
    record: &TargetRecord,
    canonical: PathBuf,
    identifier: &str,
) -> Result<(), LpmError> {
    if target.symlink_metadata().is_err() {
        return Ok(());
    }
    let owned = match record.materialization {
        Materialization::Link => std::fs::read_link(target).is_ok_and(|path| path == canonical),
        Materialization::Copy => {
            std::fs::read_to_string(target.join(COPY_MARKER)).is_ok_and(|content| {
                serde_json::from_str::<serde_json::Value>(&content)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("id")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(identifier)
            })
        }
    };
    if !owned {
        return Err(LpmError::Registry(format!(
            "refusing to remove target that is no longer LPM-managed: {}",
            target.display()
        )));
    }
    let metadata = std::fs::symlink_metadata(target)?;
    if metadata.file_type().is_symlink() || metadata.is_file() {
        std::fs::remove_file(target)?;
    } else {
        std::fs::remove_dir_all(target)?;
    }
    Ok(())
}

pub fn inventory(
    project_dir: &Path,
    include_global: bool,
) -> Result<Vec<ManagedInventory>, LpmError> {
    let mut result = inventory_scope(&Store::for_scope(Scope::Project, project_dir)?)?;
    if include_global {
        result.extend(inventory_scope(&Store::for_scope(
            Scope::Global,
            project_dir,
        )?)?);
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

fn inventory_scope(store: &Store) -> Result<Vec<ManagedInventory>, LpmError> {
    let state = load_state(store)?;
    Ok(state
        .skills
        .values()
        .map(|record| {
            let canonical = store.root.join(&record.canonical_dir);
            let agents: Vec<_> = record
                .targets
                .iter()
                .filter_map(|(agent, target)| target.enabled.then_some(*agent))
                .collect();
            let healthy = canonical.is_dir()
                && record.targets.iter().all(|(_, target)| {
                    !target.enabled || target_is_owned(Path::new(&target.path), target, &canonical)
                });
            ManagedInventory {
                name: record.name.clone(),
                description: record.description.clone(),
                source: record.source.display(),
                scope: store.scope.as_str().into(),
                context_tokens: record.context_tokens,
                agents,
                healthy,
            }
        })
        .collect())
}

pub fn external_inventory(
    project_dir: &Path,
    include_global: bool,
) -> Result<Vec<ExternalInventory>, LpmError> {
    let managed_targets = managed_target_paths(project_dir, include_global)?;
    let mut result = scan_external_scope(Scope::Project, project_dir, &managed_targets)?;
    if include_global {
        result.extend(scan_external_scope(
            Scope::Global,
            project_dir,
            &managed_targets,
        )?);
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

fn managed_target_paths(
    project_dir: &Path,
    include_global: bool,
) -> Result<BTreeSet<PathBuf>, LpmError> {
    let mut paths = BTreeSet::new();
    for store in stores_for(project_dir, include_global)? {
        for record in load_state(&store)?.skills.values() {
            let canonical = store.root.join(&record.canonical_dir);
            for target in record.targets.values() {
                let path = PathBuf::from(&target.path);
                if target.enabled && target_is_owned(&path, target, &canonical) {
                    paths.insert(path);
                }
            }
        }
    }
    Ok(paths)
}

fn scan_external_scope(
    scope: Scope,
    project_dir: &Path,
    managed_targets: &BTreeSet<PathBuf>,
) -> Result<Vec<ExternalInventory>, LpmError> {
    let mut result = Vec::new();
    for agent in AgentTarget::ALL {
        let root = match scope {
            Scope::Project => match agent {
                AgentTarget::Codex => project_dir.join(".agents/skills"),
                AgentTarget::ClaudeCode => project_dir.join(".claude/skills"),
                AgentTarget::Cursor => project_dir.join(".cursor/skills"),
            },
            Scope::Global => global_agent_root(agent)?,
        };
        scan_external_root(&root, agent, scope, managed_targets, &mut result)?;
    }
    if scope == Scope::Global
        && let Some(home) = dirs::home_dir()
    {
        scan_external_root(
            &home.join(".agents/skills"),
            AgentTarget::Codex,
            scope,
            managed_targets,
            &mut result,
        )?;
    }
    Ok(result)
}

fn scan_external_root(
    root: &Path,
    agent: AgentTarget,
    scope: Scope,
    managed_targets: &BTreeSet<PathBuf>,
    result: &mut Vec<ExternalInventory>,
) -> Result<(), LpmError> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let skill_file = path.join("SKILL.md");
        if !skill_file.is_file() {
            continue;
        }
        if managed_targets.contains(&path) {
            continue;
        }
        result.push(ExternalInventory {
            name: entry.file_name().to_string_lossy().to_string(),
            path: path.display().to_string(),
            agent,
            scope: scope.as_str().into(),
        });
    }
    Ok(())
}

pub fn view(
    project_dir: &Path,
    selector: &str,
    include_global: bool,
    json_output: bool,
) -> Result<(), LpmError> {
    let stores = stores_for(project_dir, include_global)?;
    for store in stores {
        let state = load_state(&store)?;
        if let Some(record) = state.skills.get(selector) {
            let canonical = store.root.join(&record.canonical_dir);
            let targets: Vec<_> = record
                .targets
                .iter()
                .map(|(agent, target)| {
                    serde_json::json!({
                        "agent": agent_slug(*agent),
                        "path": target.path,
                        "enabled": target.enabled,
                        "healthy": !target.enabled || target_is_owned(Path::new(&target.path), target, &canonical),
                    })
                })
                .collect();
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "success": true,
                        "kind": "managed",
                        "name": record.name,
                        "description": record.description,
                        "source": record.source,
                        "scope": store.scope.as_str(),
                        "context_tokens": record.context_tokens,
                        "targets": targets,
                    }))
                    .unwrap()
                );
            } else {
                println!("{}", record.name);
                println!("  kind: managed");
                println!("  source: {}", record.source.display());
                println!("  context: ~{} tokens", record.context_tokens);
                for target in targets {
                    println!("  target: {}", target);
                }
            }
            return Ok(());
        }
    }
    let external = external_inventory(project_dir, include_global)?;
    let matches: Vec<_> = external
        .into_iter()
        .filter(|skill| skill.name == selector)
        .collect();
    match matches.as_slice() {
        [] => {}
        [skill] => return print_external_view(skill, json_output),
        _ => {
            return Err(LpmError::Registry(format!(
                "external skill `{selector}` exists for multiple agent targets; use `lpm skills list --kind external` to choose its location"
            )));
        }
    }
    Err(LpmError::Registry(format!(
        "skill `{selector}` was not found"
    )))
}

fn print_external_view(skill: &ExternalInventory, json_output: bool) -> Result<(), LpmError> {
    let path = PathBuf::from(&skill.path).join("SKILL.md");
    let content = std::fs::read_to_string(&path)?;
    let findings: Vec<_> = lpm_security::skill_security::scan_skill_content(&content)
        .into_iter()
        .map(|finding| {
            serde_json::json!({
                "category": finding.category,
                "line": finding.line_number,
            })
        })
        .collect();
    let context_tokens = content.chars().count().div_ceil(4);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "kind": "external",
                "name": skill.name,
                "path": skill.path,
                "agent": agent_slug(skill.agent),
                "scope": skill.scope,
                "context_tokens": context_tokens,
                "security_findings": findings,
            }))
            .unwrap()
        );
    } else {
        println!("{}", skill.name);
        println!("  kind: external");
        println!("  path: {}", skill.path);
        println!("  agent: {}", agent_slug(skill.agent));
        println!("  scope: {}", skill.scope);
        println!("  context: ~{context_tokens} tokens");
        println!("  security findings: {}", findings.len());
    }
    Ok(())
}

pub fn doctor(project_dir: &Path, include_global: bool, json_output: bool) -> Result<(), LpmError> {
    let mut rows = Vec::new();
    for store in stores_for(project_dir, include_global)? {
        for record in load_state(&store)?.skills.values() {
            let canonical = store.root.join(&record.canonical_dir);
            for (agent, target) in &record.targets {
                rows.push(serde_json::json!({
                    "name": record.name,
                    "agent": agent_slug(*agent),
                    "path": target.path,
                    "enabled": target.enabled,
                    "canonical_exists": canonical.is_dir(),
                    "healthy": !target.enabled || target_is_owned(Path::new(&target.path), target, &canonical),
                }));
            }
        }
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"success": true, "targets": rows}))
                .unwrap()
        );
    } else if rows.is_empty() {
        super::install_ui::warn("No managed standalone skills to diagnose");
    } else {
        for row in &rows {
            let healthy = row
                .get("healthy")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            println!("{} {}", if healthy { "✓" } else { "!" }, row);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum Mutation {
    Remove,
    Enable,
    Disable,
}

pub fn mutate(
    project_dir: &Path,
    args: ManageArgs,
    mutation: Mutation,
    json_output: bool,
) -> Result<(), LpmError> {
    let store = Store::for_scope(
        if args.global {
            Scope::Global
        } else {
            Scope::Project
        },
        project_dir,
    )?;
    let mut state = load_state(&store)?;
    let names = select_record_names(&state, &args)?;
    let changes = mutation_changes(&store, &state, &names, &args.agent, mutation)?;
    preflight_mutation(&store, &state, &names, &args.agent, mutation)?;
    if args.dry_run || !json_output {
        print_changes(&changes, json_output);
    }
    if args.dry_run {
        return Ok(());
    }
    require_confirmation(args.yes, json_output, "Apply the managed skill changes?")?;
    let mut records_to_remove = Vec::new();
    for name in names {
        let Some(record) = state.skills.get(&name).cloned() else {
            continue;
        };
        let agents: Vec<_> = if args.agent.is_empty() {
            record.targets.keys().copied().collect()
        } else {
            args.agent.clone()
        };
        match mutation {
            Mutation::Enable => {
                let canonical = store.root.join(&record.canonical_dir);
                if !canonical.is_dir() {
                    return Err(LpmError::Registry(format!(
                        "cannot enable `{}` because its managed content is missing; run `lpm skills update {}`",
                        record.name, record.name
                    )));
                }
                for agent in agents {
                    let Some(target) = state
                        .skills
                        .get_mut(&name)
                        .and_then(|record| record.targets.get_mut(&agent))
                    else {
                        continue;
                    };
                    let path = PathBuf::from(&target.path);
                    if path.symlink_metadata().is_ok() {
                        remove_owned_target(&path, target, canonical.clone(), &record.name)?;
                    }
                    target.materialization = materialize_target(
                        &canonical,
                        &path,
                        target.materialization,
                        &record.name,
                    )?;
                    target.enabled = true;
                }
            }
            Mutation::Disable => {
                let canonical = store.root.join(&record.canonical_dir);
                for agent in agents {
                    let Some(target) = state
                        .skills
                        .get_mut(&name)
                        .and_then(|record| record.targets.get_mut(&agent))
                    else {
                        continue;
                    };
                    remove_owned_target(
                        Path::new(&target.path),
                        target,
                        canonical.clone(),
                        &record.name,
                    )?;
                    target.enabled = false;
                }
            }
            Mutation::Remove => {
                let canonical = store.root.join(&record.canonical_dir);
                for agent in agents {
                    let Some(target) = record.targets.get(&agent) else {
                        continue;
                    };
                    remove_owned_target(
                        Path::new(&target.path),
                        target,
                        canonical.clone(),
                        &record.name,
                    )?;
                    if let Some(record) = state.skills.get_mut(&name) {
                        record.targets.remove(&agent);
                    }
                }
                if state
                    .skills
                    .get(&name)
                    .is_some_and(|record| record.targets.is_empty())
                {
                    records_to_remove.push(name);
                }
            }
        }
    }
    for name in records_to_remove {
        if let Some(record) = state.skills.remove(&name) {
            let canonical = store.root.join(record.canonical_dir);
            if canonical.is_dir() {
                std::fs::remove_dir_all(canonical)?;
            }
        }
    }
    write_state(&store, &state)?;
    if json_output {
        print_applied_changes(&changes);
    } else {
        super::install_ui::done("Managed skill changes applied");
    }
    Ok(())
}

pub fn prune(project_dir: &Path, args: PruneArgs, json_output: bool) -> Result<(), LpmError> {
    let store = Store::for_scope(
        if args.global {
            Scope::Global
        } else {
            Scope::Project
        },
        project_dir,
    )?;
    let mut state = load_state(&store)?;
    let plan = prune_plan(&store, &state);
    if args.dry_run || !json_output {
        print_changes(&plan.changes, json_output);
    }
    if args.dry_run || plan.changes.is_empty() {
        return Ok(());
    }
    require_confirmation(args.yes, json_output, "Prune stale managed skill records?")?;
    for (name, agent) in &plan.orphaned_targets {
        let Some(record) = state.skills.get(name) else {
            continue;
        };
        let Some(target) = record.targets.get(agent) else {
            continue;
        };
        remove_owned_target(
            Path::new(&target.path),
            target,
            store.root.join(&record.canonical_dir),
            &record.name,
        )?;
    }
    for name in &plan.records_to_remove {
        if let Some(record) = state.skills.remove(name) {
            let canonical = store.root.join(record.canonical_dir);
            if canonical.is_dir() {
                std::fs::remove_dir_all(canonical)?;
            }
        }
    }
    for (name, agent) in &plan.stale_target_records {
        if !plan.records_to_remove.contains(name)
            && let Some(record) = state.skills.get_mut(name)
        {
            record.targets.remove(agent);
        }
    }
    write_state(&store, &state)?;
    if json_output {
        print_applied_changes(&plan.changes);
    } else {
        super::install_ui::done("Pruned stale managed skill state");
    }
    Ok(())
}

#[derive(Debug, Default)]
struct PrunePlan {
    changes: Vec<PlannedChange>,
    records_to_remove: BTreeSet<String>,
    stale_target_records: BTreeSet<(String, AgentTarget)>,
    orphaned_targets: BTreeSet<(String, AgentTarget)>,
}

fn prune_plan(store: &Store, state: &ManagedState) -> PrunePlan {
    let mut plan = PrunePlan::default();
    for (name, record) in &state.skills {
        let canonical = store.root.join(&record.canonical_dir);
        if !canonical.is_dir() {
            plan.records_to_remove.insert(name.clone());
            plan.changes.push(PlannedChange {
                action: "remove stale managed record".into(),
                path: store.state_path().join(name),
            });
            for (agent, target) in &record.targets {
                if target_is_owned(Path::new(&target.path), target, &canonical) {
                    plan.orphaned_targets.insert((name.clone(), *agent));
                    plan.changes.push(PlannedChange {
                        action: "remove orphaned managed target".into(),
                        path: PathBuf::from(&target.path),
                    });
                }
            }
            continue;
        }

        for (agent, target) in &record.targets {
            if target.enabled && !target_is_owned(Path::new(&target.path), target, &canonical) {
                plan.stale_target_records.insert((name.clone(), *agent));
                plan.changes.push(PlannedChange {
                    action: "remove stale managed target record".into(),
                    path: store.state_path().join(format!("{name}-{agent:?}")),
                });
            }
        }
        if record.targets.is_empty()
            || record
                .targets
                .keys()
                .all(|agent| plan.stale_target_records.contains(&(name.clone(), *agent)))
        {
            plan.records_to_remove.insert(name.clone());
            plan.changes.push(PlannedChange {
                action: "remove stale managed record".into(),
                path: store.state_path().join(name),
            });
            plan.changes.push(PlannedChange {
                action: "remove unreferenced managed content".into(),
                path: canonical,
            });
        }
    }
    plan
}

pub async fn update(
    project_dir: &Path,
    args: ManageArgs,
    json_output: bool,
) -> Result<(), LpmError> {
    let store = Store::for_scope(
        if args.global {
            Scope::Global
        } else {
            Scope::Project
        },
        project_dir,
    )?;
    let state = load_state(&store)?;
    let names = select_record_names(&state, &args)?;
    let mut updates = Vec::new();
    for name in names {
        let record = state.skills.get(&name).ok_or_else(|| {
            LpmError::Registry(format!("managed skill `{name}` is no longer present"))
        })?;
        let input = update_input(&record.source);
        let tree = source::load(&input, project_dir).await?;
        let discovered = source::discover(&tree, true)?;
        let skill = discovered
            .into_iter()
            .find(|skill| skill.name == record.name)
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "updated source no longer contains managed skill `{}`",
                    record.name
                ))
            })?;
        let agents: Vec<_> = record
            .targets
            .iter()
            .filter_map(|(agent, target)| target.enabled.then_some(*agent))
            .collect();
        source::ensure_agents_are_compatible(&[&skill], &agents)?;
        let copy = record
            .targets
            .values()
            .any(|target| target.materialization == Materialization::Copy);
        let plan = plan_install(&store, &tree, &[&skill], &agents, copy)?;
        let current = canonical_skill_text(&store.root.join(&record.canonical_dir))?;
        let candidate = source_skill_text(&tree, &skill)?;
        let previous_findings = count_security_findings(&current);
        let candidate_findings = skill.findings.len();
        updates.push(PendingUpdate {
            tree,
            skill,
            plan,
            diff: bounded_diff(&current, &candidate),
            previous_findings,
            candidate_findings,
        });
    }
    let changes: Vec<_> = updates
        .iter()
        .flat_map(|update| update.plan.changes.clone())
        .collect();
    if args.dry_run || !json_output {
        print_update_preview(&updates, &changes, json_output);
    }
    let skills: Vec<_> = updates.iter().map(|update| &update.skill).collect();
    source::ensure_skills_are_safe(&skills)?;
    if args.dry_run {
        return Ok(());
    }
    require_confirmation(args.yes, json_output, "Apply the managed skill updates?")?;
    for update in updates {
        apply_install(&store, &update.tree, &[&update.skill], update.plan)?;
    }
    if json_output {
        print_applied_changes(&changes);
    } else {
        super::install_ui::done("Managed skill updates applied");
    }
    Ok(())
}

struct PendingUpdate {
    tree: SourceTree,
    skill: DiscoveredSkill,
    plan: InstallPlan,
    diff: String,
    previous_findings: usize,
    candidate_findings: usize,
}

fn print_update_preview(updates: &[PendingUpdate], changes: &[PlannedChange], json_output: bool) {
    if json_output {
        let updates: Vec<_> = updates
            .iter()
            .map(|update| {
                serde_json::json!({
                    "name": update.skill.name,
                    "diff": update.diff,
                    "security_findings_before": update.previous_findings,
                    "security_findings_after": update.candidate_findings,
                    "new_security_findings": update.candidate_findings.saturating_sub(update.previous_findings),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "dry_run": true,
                "updates": updates,
                "changes": changes,
            }))
            .unwrap()
        );
        return;
    }
    super::install_ui::phase("Managed skill update preview:");
    for update in updates {
        println!("  {}", update.skill.name);
        println!(
            "    security findings: {} -> {} ({} new)",
            update.previous_findings,
            update.candidate_findings,
            update
                .candidate_findings
                .saturating_sub(update.previous_findings)
        );
        if update.diff.is_empty() {
            println!("    no content changes");
        } else {
            println!("{}", update.diff);
        }
    }
    print_changes(changes, false);
}

const MAX_UPDATE_DIFF_CHARS: usize = 16 * 1024;

fn bounded_diff(current: &str, candidate: &str) -> String {
    let patch = diffy::create_patch(current, candidate).to_string();
    if patch.len() <= MAX_UPDATE_DIFF_CHARS {
        return patch;
    }
    let mut end = MAX_UPDATE_DIFF_CHARS;
    while !patch.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n… diff truncated after {MAX_UPDATE_DIFF_CHARS} bytes",
        &patch[..end]
    )
}

fn source_skill_text(tree: &SourceTree, skill: &DiscoveredSkill) -> Result<String, LpmError> {
    let mut text = String::new();
    for (path, content) in tree.files.range(skill.directory.clone()..) {
        if !path.starts_with(&skill.directory) {
            break;
        }
        let relative = path.strip_prefix(&skill.directory).map_err(|_| {
            LpmError::Registry("selected skill file escaped its source directory".into())
        })?;
        let content = std::str::from_utf8(content).map_err(|_| {
            LpmError::Registry(format!("skill `{}` contains non-text content", skill.name))
        })?;
        append_skill_text(&mut text, relative, content);
    }
    Ok(text)
}

fn canonical_skill_text(directory: &Path) -> Result<String, LpmError> {
    if !directory.exists() {
        return Ok(String::new());
    }
    if !directory.is_dir() {
        return Err(LpmError::Registry(format!(
            "managed canonical skill content is not a directory: {}",
            directory.display()
        )));
    }
    let mut files = BTreeMap::new();
    collect_skill_text_files(directory, directory, &mut files)?;
    let mut text = String::new();
    for (relative, content) in files {
        append_skill_text(&mut text, &relative, &content);
    }
    Ok(text)
}

fn collect_skill_text_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<PathBuf, String>,
) -> Result<(), LpmError> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
            return Err(LpmError::Registry(format!(
                "managed canonical content is not a regular directory tree: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_skill_text_files(root, &path, files)?;
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| LpmError::Registry("managed canonical content escaped its root".into()))?;
        let content = std::fs::read_to_string(&path).map_err(|error| {
            LpmError::Registry(format!(
                "managed canonical skill file is not readable text ({}): {error}",
                path.display()
            ))
        })?;
        files.insert(relative.to_path_buf(), content);
    }
    Ok(())
}

fn append_skill_text(destination: &mut String, relative: &Path, content: &str) {
    destination.push_str("--- ");
    destination.push_str(&relative.display().to_string());
    destination.push_str(" ---\n");
    destination.push_str(content);
    if !content.ends_with('\n') {
        destination.push('\n');
    }
}

fn count_security_findings(content: &str) -> usize {
    lpm_security::skill_security::scan_skill_content(content).len()
}

fn update_input(source: &SourceDescriptor) -> String {
    match source {
        SourceDescriptor::Github {
            repository,
            reference,
            subpath,
            ..
        } if subpath.is_empty() => format!("https://github.com/{repository}/tree/{reference}"),
        SourceDescriptor::Github {
            repository,
            reference,
            subpath,
            ..
        } => format!("https://github.com/{repository}/tree/{reference}/{subpath}"),
        SourceDescriptor::Local { path, .. } => path.clone(),
    }
}

fn mutation_changes(
    store: &Store,
    state: &ManagedState,
    names: &[String],
    agents: &[AgentTarget],
    mutation: Mutation,
) -> Result<Vec<PlannedChange>, LpmError> {
    let mut changes = Vec::new();
    for name in names {
        let record = state.skills.get(name).ok_or_else(|| {
            LpmError::Registry(format!("managed skill `{name}` is no longer present"))
        })?;
        let selected_agents: Vec<_> = if agents.is_empty() {
            record.targets.keys().copied().collect()
        } else {
            agents.to_vec()
        };
        for agent in &selected_agents {
            if let Some(target) = record.targets.get(agent) {
                changes.push(PlannedChange {
                    action: match mutation {
                        Mutation::Remove => "remove managed target".into(),
                        Mutation::Enable => "enable managed target".into(),
                        Mutation::Disable => "disable managed target".into(),
                    },
                    path: PathBuf::from(&target.path),
                });
            }
        }
        let remaining_targets = record.targets.len().saturating_sub(
            selected_agents
                .iter()
                .filter(|agent| record.targets.contains_key(agent))
                .count(),
        );
        if matches!(mutation, Mutation::Remove) && remaining_targets == 0 {
            changes.push(PlannedChange {
                action: "remove managed content".into(),
                path: store.root.join(&record.canonical_dir),
            });
        }
    }
    Ok(changes)
}

fn preflight_mutation(
    store: &Store,
    state: &ManagedState,
    names: &[String],
    agents: &[AgentTarget],
    mutation: Mutation,
) -> Result<(), LpmError> {
    for name in names {
        let record = state.skills.get(name).ok_or_else(|| {
            LpmError::Registry(format!("managed skill `{name}` is no longer present"))
        })?;
        let canonical = store.root.join(&record.canonical_dir);
        if matches!(mutation, Mutation::Enable) && !canonical.is_dir() {
            return Err(LpmError::Registry(format!(
                "cannot enable `{}` because its managed content is missing; run `lpm skills update {}`",
                record.name, record.name
            )));
        }
        let selected_agents: Vec<_> = if agents.is_empty() {
            record.targets.keys().copied().collect()
        } else {
            agents.to_vec()
        };
        for agent in selected_agents {
            let Some(target) = record.targets.get(&agent) else {
                continue;
            };
            let path = Path::new(&target.path);
            if path.symlink_metadata().is_ok() && !target_is_owned(path, target, &canonical) {
                return Err(LpmError::Registry(format!(
                    "refusing to modify target that is no longer LPM-managed: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

fn select_record_names(state: &ManagedState, args: &ManageArgs) -> Result<Vec<String>, LpmError> {
    if args.all {
        return Ok(state.skills.keys().cloned().collect());
    }
    if args.selectors.is_empty() {
        return Err(LpmError::Registry(
            "select managed skills by name or pass `--all`".into(),
        ));
    }
    let selected: BTreeSet<_> = args.selectors.iter().cloned().collect();
    for name in &selected {
        if !state.skills.contains_key(name) {
            return Err(LpmError::Registry(format!(
                "managed skill `{name}` was not found"
            )));
        }
    }
    Ok(selected.into_iter().collect())
}

fn print_changes(changes: &[PlannedChange], json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"success": true, "dry_run": true, "changes": changes}),
            )
            .unwrap()
        );
    } else if changes.is_empty() {
        super::install_ui::phase("No managed skill changes are needed");
    } else {
        super::install_ui::phase("Planned filesystem changes:");
        for change in changes {
            println!("  {} {}", change.action, change.path.display());
        }
    }
}

fn print_applied_changes(changes: &[PlannedChange]) {
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"success": true, "dry_run": false, "changes": changes}),
        )
        .unwrap()
    );
}

fn require_confirmation(yes: bool, json_output: bool, prompt: &str) -> Result<(), LpmError> {
    if yes {
        return Ok(());
    }
    if json_output || !std::io::stdin().is_terminal() {
        return Err(LpmError::Registry(
            "non-interactive managed skill mutation requires `--yes` after reviewing `--dry-run`"
                .into(),
        ));
    }
    if cliclack::confirm(prompt)
        .initial_value(false)
        .interact()
        .map_err(crate::prompt::prompt_err)?
    {
        Ok(())
    } else {
        Err(LpmError::Script(
            "skill operation cancelled; no files changed".into(),
        ))
    }
}

fn stores_for(project_dir: &Path, include_global: bool) -> Result<Vec<Store>, LpmError> {
    let mut stores = vec![Store::for_scope(Scope::Project, project_dir)?];
    if include_global {
        stores.push(Store::for_scope(Scope::Global, project_dir)?);
    }
    Ok(stores)
}

fn load_state(store: &Store) -> Result<ManagedState, LpmError> {
    let path = store.state_path();
    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ManagedState::default());
        }
        Err(error) => return Err(LpmError::Io(error)),
    };
    let state: ManagedState = serde_json::from_str(&content).map_err(|error| {
        LpmError::Registry(format!("failed to parse {}: {error}", path.display()))
    })?;
    if state.state_version > STATE_VERSION {
        return Err(LpmError::Registry(format!(
            "{} has state version {} but this lpm supports up to {STATE_VERSION}",
            path.display(),
            state.state_version
        )));
    }
    Ok(state)
}

fn write_state(store: &Store, state: &ManagedState) -> Result<(), LpmError> {
    std::fs::create_dir_all(&store.root)?;
    let content = serde_json::to_vec_pretty(state).map_err(|error| {
        LpmError::Registry(format!("failed to serialize managed skill state: {error}"))
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(&store.root).map_err(LpmError::Io)?;
    temporary.write_all(&content).map_err(LpmError::Io)?;
    temporary.write_all(b"\n").map_err(LpmError::Io)?;
    temporary.flush().map_err(LpmError::Io)?;
    temporary
        .persist(store.state_path())
        .map_err(|error| LpmError::Io(error.error))?;
    Ok(())
}

fn global_agent_root(agent: AgentTarget) -> Result<PathBuf, LpmError> {
    let home = dirs::home_dir().ok_or_else(|| {
        LpmError::Registry("could not determine home directory for global agent skills".into())
    })?;
    Ok(match agent {
        AgentTarget::Codex => std::env::var_os("CODEX_HOME")
            .map_or_else(|| home.join(".codex"), PathBuf::from)
            .join("skills"),
        AgentTarget::ClaudeCode => home.join(".claude/skills"),
        AgentTarget::Cursor => home.join(".cursor/skills"),
    })
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..8])
}

fn agent_slug(agent: AgentTarget) -> &'static str {
    match agent {
        AgentTarget::Codex => "codex",
        AgentTarget::ClaudeCode => "claude-code",
        AgentTarget::Cursor => "cursor",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn source_tree() -> SourceTree {
        SourceTree {
            descriptor: SourceDescriptor::Local {
                path: "/tmp/skills".into(),
                digest: "a".repeat(64),
            },
            files: BTreeMap::from([(
                PathBuf::from("release/SKILL.md"),
                b"---\nname: release-notes\ndescription: Create useful release notes\n---\nWrite release notes from changes.".to_vec(),
            )]),
        }
    }

    fn discovered_skill() -> DiscoveredSkill {
        DiscoveredSkill::for_test("release-notes")
    }

    #[test]
    fn project_store_places_codex_target_in_agents_skills() {
        let project = tempfile::tempdir().unwrap();
        let store = Store::for_scope(Scope::Project, project.path()).unwrap();

        let target = store
            .target_path(AgentTarget::Codex, "release-notes")
            .unwrap();

        assert_eq!(target, project.path().join(".agents/skills/release-notes"));
    }

    #[test]
    fn install_plan_rejects_existing_external_target() {
        let project = tempfile::tempdir().unwrap();
        let target = project.path().join(".agents/skills/release-notes");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("SKILL.md"), "external").unwrap();
        let store = Store::for_scope(Scope::Project, project.path()).unwrap();
        let tree = source_tree();
        let skill = discovered_skill();

        let error =
            plan_install(&store, &tree, &[&skill], &[AgentTarget::Codex], false).unwrap_err();

        assert!(error.to_string().contains("external skill target"));
    }

    #[test]
    fn managed_state_round_trips_through_atomic_writer() {
        let project = tempfile::tempdir().unwrap();
        let store = Store::for_scope(Scope::Project, project.path()).unwrap();
        let mut state = ManagedState::default();
        state.skills.insert(
            "release-notes".into(),
            ManagedSkillRecord {
                name: "release-notes".into(),
                description: "Create release notes".into(),
                source: source_tree().descriptor,
                canonical_dir: "sources/a/b/release-notes".into(),
                context_tokens: 12,
                targets: BTreeMap::new(),
            },
        );

        write_state(&store, &state).unwrap();
        let loaded = load_state(&store).unwrap();

        assert!(loaded.skills.contains_key("release-notes"));
    }
}
