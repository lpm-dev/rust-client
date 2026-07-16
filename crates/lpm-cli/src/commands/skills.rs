use crate::cli::{
    SkillsAddArgs, SkillsArgs, SkillsCommand, SkillsListArgs, SkillsRemoveArgs, SkillsScopeArgs,
    SkillsToggleArgs, SkillsUpdateArgs, SkillsValidateArgs, SkillsViewArgs,
};
use crate::install_ui;
use crate::prompt::prompt_err;
use crate::skills_inventory;
use crate::skills_model::{
    AgentTarget, ManagedSkill, SkillBinding, SkillManifest, SkillScope, managed_root,
};
use crate::skills_source::{
    DiscoveredSkill, SkillAudit, audit_skill, copy_skill_tree, discover_skills, resolve_source,
};
use lpm_common::color::Painted;
use lpm_common::{LpmError, PackageName, is_safe_skill_name};
use lpm_registry::RegistryClient;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Manage agent skills from GitHub, local directories, and the LPM Registry.
pub async fn run(
    client: &RegistryClient,
    args: SkillsArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match args.action {
        SkillsCommand::Add(args) => run_add(client, args, project_dir, json_output).await,
        SkillsCommand::List(args) => run_list(args, project_dir, json_output),
        SkillsCommand::View(args) => run_view(args, project_dir, json_output),
        SkillsCommand::Remove(args) => run_remove(args, project_dir, json_output),
        SkillsCommand::Clean => run_package_clean(project_dir, json_output),
        SkillsCommand::Enable(args) => run_toggle(args, true, project_dir, json_output),
        SkillsCommand::Disable(args) => run_toggle(args, false, project_dir, json_output),
        SkillsCommand::Update(args) => run_update(args, project_dir, json_output).await,
        SkillsCommand::Doctor(args) => run_doctor(args, project_dir, json_output),
        SkillsCommand::Validate(args) => run_validate(args, project_dir, json_output),
    }
}

async fn run_add(
    client: &RegistryClient,
    mut args: SkillsAddArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let started = Instant::now();
    let interactive = is_interactive(args.yes, json_output);
    let source = match args.source.take() {
        Some(source) => source,
        None if interactive => cliclack::input("Skill source")
            .placeholder("vercel-labs/agent-skills, https://github.com/org/repo, or ./skills")
            .interact::<String>()
            .map_err(prompt_err)?,
        None => {
            return Err(LpmError::Registry(
                "specify a source or run `lpm skills add` in an interactive terminal".into(),
            ));
        }
    };

    if source.starts_with("@lpm.dev/") {
        return run_package_add(client, &source, &args, project_dir, json_output).await;
    }
    if !json_output {
        install_ui::phase(&format!("Resolving {}", install_ui::cyan(&source)));
    }
    let resolved = resolve_source(&source).await?;
    let discovered = discover_skills(&resolved.root)?;
    if discovered.is_empty() {
        return Err(LpmError::Registry(format!(
            "no SKILL.md files found in `{source}`"
        )));
    }
    if args.list {
        print_discovered(&source, &discovered, json_output);
        return Ok(());
    }

    let selected = select_skills(&discovered, &args, interactive)?;
    let scope = select_scope(&args, interactive)?;
    let agents = select_agents(&args, scope, project_dir, interactive)?;
    let audited: Vec<_> = selected
        .iter()
        .map(|skill| audit_skill(skill).map(|audit| (skill, audit)))
        .collect::<Result<_, _>>()?;
    let blocked: Vec<_> = audited
        .iter()
        .filter(|(_, audit)| !audit.findings.is_empty())
        .collect();
    if !blocked.is_empty() {
        let details = blocked
            .iter()
            .map(|(skill, audit)| format!("{}: {}", skill.name, audit.findings.join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(LpmError::Registry(format!(
            "refusing to install skills with blocked security findings: {details}"
        )));
    }

    if interactive {
        print_install_plan(&source, &selected, scope, &agents, args.copy);
        let confirmed = cliclack::confirm("Install selected skills?")
            .initial_value(true)
            .interact()
            .map_err(prompt_err)?;
        if !confirmed {
            return Err(LpmError::Registry("skills installation cancelled".into()));
        }
    }

    let mut manifest = SkillManifest::load(scope, project_dir)?;
    let requested_bindings: Vec<_> = agents
        .into_iter()
        .map(|agent| SkillBinding {
            agent,
            enabled: true,
            copied: args.copy,
        })
        .collect();
    preflight_install(&manifest, &audited, &requested_bindings, scope, project_dir)?;
    let mut installed = Vec::with_capacity(audited.len());
    for (skill, audit) in audited {
        match install_skill(
            &mut manifest,
            skill,
            &audit,
            InstallOptions {
                source: &resolved.source,
                source_kind: resolved.source_kind,
                resolved_revision: resolved.resolved_revision.as_deref(),
                scope,
                bindings: &requested_bindings,
                project_dir,
            },
        ) {
            Ok(managed) => installed.push(managed),
            Err(error) => {
                for managed in installed.iter().rev() {
                    let _ = remove_managed_skill(managed, project_dir);
                }
                return Err(error);
            }
        }
    }
    if let Err(error) = manifest.save(scope, project_dir) {
        for managed in installed.iter().rev() {
            let _ = remove_managed_skill(managed, project_dir);
        }
        return Err(error);
    }

    if json_output {
        let skills: Vec<_> = installed.iter().map(skill_json).collect();
        print_json(serde_json::json!({
            "success": true,
            "action": "add",
            "source": source,
            "scope": scope.as_str(),
            "skills": skills,
            "count": installed.len(),
            "duration_ms": started.elapsed().as_millis() as u64,
        }));
    } else {
        for skill in &installed {
            install_ui::done(&format!(
                "Enabled {} for {}",
                install_ui::yellow(&skill.name),
                skill
                    .bindings
                    .iter()
                    .map(|binding| binding.agent.display_name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        install_ui::done(&format!(
            "Added {} {} in {}",
            installed.len(),
            if installed.len() == 1 {
                "skill"
            } else {
                "skills"
            },
            install_ui::status_ok(&install_ui::format_duration(started.elapsed()))
        ));
    }
    Ok(())
}

async fn run_package_add(
    client: &RegistryClient,
    source: &str,
    args: &SkillsAddArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args.global || args.project || !args.agents.is_empty() || args.all_agents || args.copy {
        return Err(LpmError::Registry(
            "package-published skills always belong to the installed package in `.lpm/skills`; agent targets and skill scope apply only to standalone sources".into(),
        ));
    }
    if args.all && !args.skills.is_empty() {
        return Err(LpmError::Registry(
            "`--all` cannot be combined with `--skill`".into(),
        ));
    }
    let package = PackageName::parse(source)?;
    if !json_output {
        install_ui::phase(&format!(
            "Fetching package skills for {}",
            install_ui::cyan(&package.scoped())
        ));
    }
    let response = client.get_skills(&package.short(), None).await?;
    if response.skills.is_empty() {
        if json_output {
            print_json(serde_json::json!({
                "success": true,
                "action": "add",
                "package": package.scoped(),
                "installed": 0,
            }));
        } else {
            install_ui::warn("Package has no published skills");
        }
        return Ok(());
    }

    let selected = select_package_skills(&response.skills, &args.skills)?;
    if args.list {
        print_package_discovered(source, &selected, json_output);
        return Ok(());
    }

    let mut files = Vec::with_capacity(selected.len());
    for skill in selected {
        if !is_safe_skill_name(&skill.name) {
            return Err(LpmError::Registry(format!(
                "package `{}` returned an unsafe skill name `{}`",
                package.scoped(),
                skill.name
            )));
        }
        let content = skill
            .raw_content
            .as_deref()
            .or(skill.content.as_deref())
            .filter(|content| !content.is_empty())
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "package `{}` returned empty content for skill `{}`",
                    package.scoped(),
                    skill.name
                ))
            })?;
        files.push((skill.name.as_str(), content));
    }

    let root = project_dir.join(".lpm").join("skills");
    std::fs::create_dir_all(&root).map_err(LpmError::Io)?;
    let staged = tempfile::Builder::new()
        .prefix(".lpm-skills-stage-")
        .tempdir_in(&root)
        .map_err(LpmError::Io)?;
    for (name, content) in &files {
        std::fs::write(staged.path().join(format!("{name}.md")), content).map_err(LpmError::Io)?;
    }

    let destination = root.join(package.short());
    let backup = tempfile::Builder::new()
        .prefix(".lpm-skills-backup-")
        .tempdir_in(&root)
        .map_err(LpmError::Io)?;
    let backup_path = backup.path().to_path_buf();
    drop(backup);

    let had_destination = destination.exists();
    if had_destination {
        std::fs::rename(&destination, &backup_path).map_err(LpmError::Io)?;
    }
    if let Err(error) = std::fs::rename(staged.path(), &destination) {
        if had_destination {
            let _ = std::fs::rename(&backup_path, &destination);
        }
        return Err(LpmError::Io(error));
    }
    if had_destination {
        std::fs::remove_dir_all(&backup_path).map_err(LpmError::Io)?;
    }
    crate::commands::install::ensure_skills_gitignore(project_dir);

    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "action": "add",
            "package": package.scoped(),
            "installed": files.len(),
            "directory": destination,
        }));
    } else {
        install_ui::done(&format!(
            "Added {} package-published {}",
            files.len(),
            plural(files.len(), "skill")
        ));
        eprintln!("  {}", install_ui::cyan(&destination.display().to_string()));
    }
    Ok(())
}

fn select_package_skills<'a>(
    skills: &'a [lpm_registry::Skill],
    requested: &[String],
) -> Result<Vec<&'a lpm_registry::Skill>, LpmError> {
    if requested.is_empty() {
        return Ok(skills.iter().collect());
    }
    let mut selected: Vec<&lpm_registry::Skill> = Vec::with_capacity(requested.len());
    for name in requested {
        let skill = skills
            .iter()
            .find(|skill| skill.name == *name)
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "package does not publish skill `{name}`; available: {}",
                    skills
                        .iter()
                        .map(|skill| skill.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
        if selected.iter().any(|selected| selected.name == skill.name) {
            return Err(LpmError::Registry(format!(
                "package skill `{name}` was selected more than once"
            )));
        }
        selected.push(skill);
    }
    Ok(selected)
}

fn print_package_discovered(source: &str, skills: &[&lpm_registry::Skill], json_output: bool) {
    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "source": source,
            "skills": skills.iter().map(|skill| serde_json::json!({
                "name": skill.name,
                "description": skill.description,
            })).collect::<Vec<_>>(),
            "count": skills.len(),
        }));
        return;
    }
    install_ui::phase(&format!("Package skills from {}", install_ui::cyan(source)));
    for skill in skills {
        eprintln!(
            "  {:<24} {}",
            skill.name,
            skill
                .description
                .as_deref()
                .unwrap_or("Package-published skill")
                .dimmed()
        );
    }
    install_ui::done(&format!(
        "Found {} package-published {}",
        skills.len(),
        plural(skills.len(), "skill")
    ));
}

fn run_package_clean(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let root = project_dir.join(".lpm").join("skills");
    let file_count = match count_files_recursive(&root) {
        Ok(file_count) => file_count,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if json_output {
                print_json(serde_json::json!({
                    "success": true,
                    "action": "clean",
                    "files_removed": 0,
                }));
            } else {
                install_ui::warn("No package-published skills to clean");
            }
            return Ok(());
        }
        Err(error) => return Err(LpmError::Io(error)),
    };
    std::fs::remove_dir_all(&root).map_err(LpmError::Io)?;
    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "action": "clean",
            "files_removed": file_count,
        }));
    } else {
        install_ui::done(&format!(
            "Removed {file_count} package-published {}",
            plural(file_count, "skill file")
        ));
    }
    Ok(())
}

fn print_discovered(source: &str, skills: &[DiscoveredSkill], json_output: bool) {
    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "source": source,
            "skills": skills.iter().map(|skill| serde_json::json!({
                "name": skill.name,
                "description": skill.description,
            })).collect::<Vec<_>>(),
            "count": skills.len(),
        }));
        return;
    }
    install_ui::phase(&format!("Skills from {}", install_ui::cyan(source)));
    for skill in skills {
        eprintln!("  {:<24} {}", skill.name, skill.description.dimmed());
    }
    install_ui::done(&format!(
        "Found {} {}",
        skills.len(),
        plural(skills.len(), "skill")
    ));
}

fn select_skills(
    discovered: &[DiscoveredSkill],
    args: &SkillsAddArgs,
    interactive: bool,
) -> Result<Vec<DiscoveredSkill>, LpmError> {
    if args.all && !args.skills.is_empty() {
        return Err(LpmError::Registry(
            "`--all` cannot be combined with `--skill`".into(),
        ));
    }
    if args.all {
        return Ok(discovered.to_vec());
    }
    if !args.skills.is_empty() {
        let mut selected = Vec::with_capacity(args.skills.len());
        for requested in &args.skills {
            let skill = discovered
                .iter()
                .find(|skill| skill.name == *requested)
                .ok_or_else(|| {
                    LpmError::Registry(format!(
                        "source does not contain skill `{requested}`; available: {}",
                        discovered
                            .iter()
                            .map(|skill| skill.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?;
            selected.push(skill.clone());
        }
        return Ok(selected);
    }
    if discovered.len() == 1 {
        return Ok(vec![discovered[0].clone()]);
    }
    if !interactive {
        return Err(LpmError::Registry(format!(
            "source contains multiple skills; pass `--skill <name>` or `--all`: {}",
            discovered
                .iter()
                .map(|skill| skill.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    let mut select = cliclack::multiselect("Select skills  (space=toggle  a=all  enter=confirm)");
    for (index, skill) in discovered.iter().enumerate() {
        select = select.item(index, &skill.name, &skill.description);
    }
    let indices: Vec<usize> = select.interact().map_err(prompt_err)?;
    if indices.is_empty() {
        return Err(LpmError::Registry("select at least one skill".into()));
    }
    Ok(indices
        .into_iter()
        .filter_map(|index| discovered.get(index).cloned())
        .collect())
}

fn select_scope(args: &SkillsAddArgs, interactive: bool) -> Result<SkillScope, LpmError> {
    if args.global {
        return Ok(SkillScope::Global);
    }
    if args.project || !interactive {
        return Ok(SkillScope::Project);
    }
    let choice: &str = cliclack::select("Install scope")
        .item("project", "Project", "available to this repository")
        .item("global", "Global", "available in every repository")
        .initial_value("project")
        .interact()
        .map_err(prompt_err)?;
    Ok(match choice {
        "global" => SkillScope::Global,
        _ => SkillScope::Project,
    })
}

fn select_agents(
    args: &SkillsAddArgs,
    scope: SkillScope,
    project_dir: &Path,
    interactive: bool,
) -> Result<Vec<AgentTarget>, LpmError> {
    if args.all_agents && !args.agents.is_empty() {
        return Err(LpmError::Registry(
            "`--all-agents` cannot be combined with `--agent`".into(),
        ));
    }
    if args.all_agents {
        return Ok(AgentTarget::ALL.to_vec());
    }
    if !args.agents.is_empty() {
        return parse_agents(&args.agents);
    }
    if !interactive {
        return Err(LpmError::Registry(
            "non-interactive installs require `--agent <name>` or `--all-agents`".into(),
        ));
    }

    let detected: Vec<_> = AgentTarget::ALL
        .into_iter()
        .filter(|agent| agent.is_detected(scope, project_dir))
        .collect();
    let mut select =
        cliclack::multiselect("Enable for agents  (space=toggle  a=all  enter=confirm)");
    for (index, agent) in AgentTarget::ALL.iter().enumerate() {
        let hint = if detected.contains(agent) {
            "detected"
        } else {
            "creates its skill directory"
        };
        select = select.item(index, agent.display_name(), hint);
    }
    let initial: Vec<usize> = AgentTarget::ALL
        .iter()
        .enumerate()
        .filter_map(|(index, agent)| detected.contains(agent).then_some(index))
        .collect();
    let indices: Vec<usize> = select
        .initial_values(initial)
        .interact()
        .map_err(prompt_err)?;
    if indices.is_empty() {
        return Err(LpmError::Registry("select at least one agent".into()));
    }
    Ok(indices
        .into_iter()
        .map(|index| AgentTarget::ALL[index])
        .collect())
}

fn print_install_plan(
    source: &str,
    skills: &[DiscoveredSkill],
    scope: SkillScope,
    agents: &[AgentTarget],
    copy: bool,
) {
    eprintln!();
    eprintln!("  {}", install_ui::section("Installation plan"));
    eprintln!("  {}  {}", "source".dimmed(), install_ui::cyan(source));
    eprintln!(
        "  {}  {}",
        "skills".dimmed(),
        skills
            .iter()
            .map(|skill| skill.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!(
        "  {}  {}",
        "scope".dimmed(),
        install_ui::cyan(scope.as_str())
    );
    eprintln!(
        "  {}  {} ({})",
        "agents".dimmed(),
        agents
            .iter()
            .map(|agent| agent.display_name())
            .collect::<Vec<_>>()
            .join(", "),
        if copy { "copy" } else { "link" }
    );
    eprintln!();
}

struct InstallOptions<'a> {
    source: &'a str,
    source_kind: &'a str,
    resolved_revision: Option<&'a str>,
    scope: SkillScope,
    bindings: &'a [SkillBinding],
    project_dir: &'a Path,
}

fn install_skill(
    manifest: &mut SkillManifest,
    skill: &DiscoveredSkill,
    audit: &SkillAudit,
    options: InstallOptions<'_>,
) -> Result<ManagedSkill, LpmError> {
    let id = managed_id(&skill.name, &audit.digest);
    if manifest
        .skills
        .iter()
        .any(|installed| installed.name == skill.name && installed.source == options.source)
    {
        return Err(LpmError::Registry(format!(
            "skill `{}` from `{}` is already managed; run `lpm skills update {}`",
            options.source, skill.name, skill.name
        )));
    }

    let root = managed_root(options.scope, options.project_dir)?;
    std::fs::create_dir_all(&root).map_err(LpmError::Io)?;
    let canonical = root.join(&id);
    if let Err(error) = copy_skill_tree(&skill.root, &canonical) {
        let _ = std::fs::remove_dir_all(&canonical);
        return Err(error);
    }
    let mut bindings: Vec<SkillBinding> = Vec::with_capacity(options.bindings.len());
    for requested in options.bindings {
        let copied = if requested.enabled {
            match install_agent_binding(
                requested.agent,
                options.scope,
                options.project_dir,
                &id,
                &canonical,
                requested.copied,
            ) {
                Ok(copied) => copied,
                Err(error) => {
                    for binding in &bindings {
                        let target = binding
                            .agent
                            .skill_root(options.scope, options.project_dir)?
                            .join(&id);
                        remove_owned_target(&target, &canonical, binding.copied, &id)?;
                    }
                    std::fs::remove_dir_all(&canonical).map_err(LpmError::Io)?;
                    return Err(error);
                }
            }
        } else {
            requested.copied
        };
        bindings.push(SkillBinding {
            agent: requested.agent,
            enabled: requested.enabled,
            copied,
        });
    }
    let managed = ManagedSkill {
        id,
        name: skill.name.clone(),
        description: skill.description.clone(),
        source: options.source.to_string(),
        source_kind: options.source_kind.to_string(),
        resolved_revision: options.resolved_revision.map(str::to_string),
        digest: audit.digest.clone(),
        scope: options.scope,
        bindings,
        estimated_tokens: audit.estimated_tokens,
        size_bytes: audit.size_bytes,
    };
    manifest.skills.push(managed.clone());
    manifest
        .skills
        .sort_by(|left, right| left.name.cmp(&right.name));
    Ok(managed)
}

fn preflight_install(
    manifest: &SkillManifest,
    audited: &[(&DiscoveredSkill, SkillAudit)],
    bindings: &[SkillBinding],
    scope: SkillScope,
    project_dir: &Path,
) -> Result<(), LpmError> {
    let root = managed_root(scope, project_dir)?;
    let mut ids = std::collections::BTreeSet::new();
    let mut targets = std::collections::BTreeSet::new();
    for (skill, audit) in audited {
        let id = managed_id(&skill.name, &audit.digest);
        if !ids.insert(id.clone()) || root.join(&id).symlink_metadata().is_ok() {
            return Err(LpmError::Registry(format!(
                "refusing to replace existing managed skill path {}",
                root.join(&id).display()
            )));
        }
        if manifest.skills.iter().any(|managed| managed.id == id) {
            return Err(LpmError::Registry(format!(
                "skill `{}` is already managed; run `lpm skills update {}`",
                skill.name, skill.name
            )));
        }
        for binding in bindings.iter().filter(|binding| binding.enabled) {
            let target = binding.agent.skill_root(scope, project_dir)?.join(&id);
            if !targets.insert(target.clone()) || target.symlink_metadata().is_ok() {
                return Err(LpmError::Registry(format!(
                    "refusing to replace existing agent skill path {}",
                    target.display()
                )));
            }
        }
    }
    Ok(())
}

fn install_agent_binding(
    agent: AgentTarget,
    scope: SkillScope,
    project_dir: &Path,
    id: &str,
    canonical: &Path,
    copy: bool,
) -> Result<bool, LpmError> {
    let root = agent.skill_root(scope, project_dir)?;
    std::fs::create_dir_all(&root).map_err(LpmError::Io)?;
    let target = root.join(id);
    if target.symlink_metadata().is_ok() {
        return Err(LpmError::Registry(format!(
            "refusing to replace existing agent skill path {}",
            target.display()
        )));
    }
    if copy {
        copy_binding_tree(canonical, &target, id)?;
        return Ok(true);
    }
    create_skill_link(canonical, &target)?;
    Ok(false)
}

#[cfg(unix)]
fn create_skill_link(canonical: &Path, target: &Path) -> Result<(), LpmError> {
    std::os::unix::fs::symlink(canonical, target).map_err(LpmError::Io)
}

#[cfg(windows)]
fn create_skill_link(canonical: &Path, target: &Path) -> Result<(), LpmError> {
    std::os::windows::fs::symlink_dir(canonical, target).map_err(LpmError::Io)
}

fn copy_binding_tree(canonical: &Path, target: &Path, id: &str) -> Result<(), LpmError> {
    let result = copy_skill_tree(canonical, target).and_then(|_| {
        std::fs::write(target.join(".lpm-skill-owner"), format!("{id}\n")).map_err(LpmError::Io)
    });
    if result.is_err() {
        let _ = std::fs::remove_dir_all(target);
    }
    result
}

fn run_list(args: SkillsListArgs, project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let skills = load_skill_inventory(args.scope, project_dir)?;
    let skills: Vec<_> = skills
        .into_iter()
        .filter(|skill| {
            args.agent.as_ref().is_none_or(|agent| {
                skill
                    .bindings
                    .iter()
                    .any(|binding| binding.agent.as_str() == agent)
            })
        })
        .collect();
    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "skills": skills.iter().map(skill_json).collect::<Vec<_>>(),
            "count": skills.len(),
        }));
        return Ok(());
    }
    if skills.is_empty() {
        install_ui::warn("No skills discovered");
        return Ok(());
    }
    print_skill_rows(&skills);
    install_ui::done(&format!(
        "{} {} discovered",
        skills.len(),
        plural(skills.len(), "skill")
    ));
    Ok(())
}

fn run_view(args: SkillsViewArgs, project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let skills = load_skill_inventory(args.scope, project_dir)?;
    let skills: Vec<_> = skills
        .into_iter()
        .filter(|managed| {
            args.skill
                .as_ref()
                .is_none_or(|skill| managed.name == *skill || managed.id == *skill)
        })
        .filter(|managed| {
            args.agent.as_ref().is_none_or(|agent| {
                managed
                    .bindings
                    .iter()
                    .any(|binding| binding.agent.as_str() == agent)
            })
        })
        .collect();
    if skills.is_empty() && args.skill.is_some() {
        return Err(LpmError::Registry("no matching skills found".into()));
    }
    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "skills": skills.iter().map(|skill| skill_view_json(skill, project_dir)).collect::<Vec<_>>(),
            "count": skills.len(),
        }));
        return Ok(());
    }
    if skills.is_empty() {
        install_ui::warn("No skills discovered");
        return Ok(());
    }
    for (index, skill) in skills.iter().enumerate() {
        if index > 0 {
            eprintln!();
        }
        print_skill_view(skill, project_dir)?;
    }
    Ok(())
}

fn run_remove(
    args: SkillsRemoveArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args.all && !args.skills.is_empty() {
        return Err(LpmError::Registry(
            "`--all` cannot be combined with skill names".into(),
        ));
    }
    let scope = mutation_scope(args.scope, project_dir);
    let mut manifest = SkillManifest::load(scope, project_dir)?;
    let requested_agents = parse_agents(&args.agents)?;
    let selected_count = manifest
        .skills
        .iter()
        .filter(|skill| skill_is_selected(skill, &args.skills, args.all))
        .count();
    if selected_count == 0 {
        if !args.all {
            let inventory = load_skill_inventory(args.scope, project_dir)?;
            if let Some(skill) = inventory
                .iter()
                .find(|skill| skill_is_selected(skill, &args.skills, false))
            {
                return match skill.source_kind.as_str() {
                    "package" => Err(LpmError::Registry(format!(
                        "`{}` is package-published; manage it through `lpm install` or `lpm remove {}`",
                        skill.name, skill.source
                    ))),
                    "external" => Err(LpmError::Registry(format!(
                        "`{}` is an externally installed agent skill; LPM will not remove it",
                        skill.name
                    ))),
                    _ => Err(LpmError::Registry(
                        "no matching managed skills found".into(),
                    )),
                };
            }
        }
        return Err(LpmError::Registry(
            "no matching managed skills found".into(),
        ));
    }
    if !args.yes && is_interactive(false, json_output) {
        let confirmed = cliclack::confirm(format!(
            "Remove {} {}?",
            selected_count,
            plural(selected_count, "skill")
        ))
        .initial_value(false)
        .interact()
        .map_err(prompt_err)?;
        if !confirmed {
            return Err(LpmError::Registry("skills removal cancelled".into()));
        }
    } else if !args.yes && !json_output {
        return Err(LpmError::Registry(
            "pass `--yes` when removing skills without an interactive terminal".into(),
        ));
    }

    for skill in manifest
        .skills
        .iter()
        .filter(|skill| skill_is_selected(skill, &args.skills, args.all))
    {
        if requested_agents.is_empty() {
            preflight_remove_skill(skill, project_dir)?;
            continue;
        }
        if !requested_agents
            .iter()
            .all(|agent| skill.bindings.iter().any(|binding| binding.agent == *agent))
        {
            return Err(LpmError::Registry(format!(
                "skill `{}` is not managed for every requested agent",
                skill.name
            )));
        }
        let canonical = managed_root(scope, project_dir)?.join(&skill.id);
        for binding in skill
            .bindings
            .iter()
            .filter(|binding| requested_agents.contains(&binding.agent))
        {
            let target = binding
                .agent
                .skill_root(scope, project_dir)?
                .join(&skill.id);
            validate_owned_target(&target, &canonical, binding.copied, &skill.id)?;
        }
    }

    let mut removed = Vec::with_capacity(selected_count);
    let mut next = Vec::with_capacity(manifest.skills.len());
    for mut skill in manifest.skills {
        if !skill_is_selected(&skill, &args.skills, args.all) {
            next.push(skill);
            continue;
        }
        if requested_agents.is_empty() {
            remove_managed_skill(&skill, project_dir)?;
            removed.push(skill.name);
            continue;
        }
        let canonical = managed_root(scope, project_dir)?.join(&skill.id);
        for binding in skill
            .bindings
            .iter()
            .filter(|binding| requested_agents.contains(&binding.agent))
        {
            let target = binding
                .agent
                .skill_root(scope, project_dir)
                .map(|root| root.join(&skill.id))?;
            remove_owned_target(&target, &canonical, binding.copied, &skill.id)?;
        }
        skill
            .bindings
            .retain(|binding| !requested_agents.contains(&binding.agent));
        if skill.bindings.is_empty() {
            if canonical.exists() {
                std::fs::remove_dir_all(&canonical).map_err(LpmError::Io)?;
            }
            removed.push(skill.name);
        } else {
            next.push(skill);
        }
    }
    manifest.skills = next;
    manifest.save(scope, project_dir)?;
    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "action": "remove",
            "removed": removed,
            "count": selected_count,
        }));
    } else {
        install_ui::done(&format!(
            "Removed {} {}",
            selected_count,
            plural(selected_count, "skill")
        ));
    }
    Ok(())
}

fn run_toggle(
    args: SkillsToggleArgs,
    enabled: bool,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if args.skills.is_empty() {
        return Err(LpmError::Registry("specify at least one skill".into()));
    }
    let scope = mutation_scope(args.scope, project_dir);
    let mut manifest = SkillManifest::load(scope, project_dir)?;
    let requested_agents = parse_agents(&args.agents)?;
    for skill in manifest.skills.iter().filter(|skill| {
        args.skills
            .iter()
            .any(|requested| requested == &skill.name || requested == &skill.id)
    }) {
        let canonical = managed_root(scope, project_dir)?.join(&skill.id);
        if !canonical.is_dir() {
            return Err(LpmError::Registry(format!(
                "managed skill content is missing for `{}`; run `lpm skills doctor`",
                skill.name
            )));
        }
        for binding in &skill.bindings {
            if !requested_agents.is_empty() && !requested_agents.contains(&binding.agent) {
                continue;
            }
            let target = binding
                .agent
                .skill_root(scope, project_dir)?
                .join(&skill.id);
            if enabled && !binding.enabled && target.symlink_metadata().is_ok() {
                return Err(LpmError::Registry(format!(
                    "refusing to replace existing agent skill path {}",
                    target.display()
                )));
            }
            if !enabled && binding.enabled {
                validate_owned_target(&target, &canonical, binding.copied, &skill.id)?;
            }
        }
    }
    let mut changed = 0usize;
    for skill in manifest.skills.iter_mut().filter(|skill| {
        args.skills
            .iter()
            .any(|requested| requested == &skill.name || requested == &skill.id)
    }) {
        let canonical = managed_root(scope, project_dir)?.join(&skill.id);
        for binding in &mut skill.bindings {
            if !requested_agents.is_empty() && !requested_agents.contains(&binding.agent) {
                continue;
            }
            let target = binding
                .agent
                .skill_root(scope, project_dir)?
                .join(&skill.id);
            if enabled && !binding.enabled {
                binding.copied = install_agent_binding(
                    binding.agent,
                    scope,
                    project_dir,
                    &skill.id,
                    &canonical,
                    binding.copied,
                )?;
                binding.enabled = true;
                changed += 1;
            } else if !enabled && binding.enabled {
                remove_owned_target(&target, &canonical, binding.copied, &skill.id)?;
                binding.enabled = false;
                changed += 1;
            }
        }
    }
    if changed == 0 {
        return Err(LpmError::Registry(
            "no matching enabled-state changes found".into(),
        ));
    }
    manifest.save(scope, project_dir)?;
    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "action": if enabled { "enable" } else { "disable" },
            "count": changed,
        }));
    } else {
        install_ui::done(&format!(
            "{} {} agent {}",
            if enabled { "Enabled" } else { "Disabled" },
            changed,
            plural(changed, "binding")
        ));
    }
    Ok(())
}

async fn run_update(
    args: SkillsUpdateArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let scope = mutation_scope(args.scope, project_dir);
    let mut manifest = SkillManifest::load(scope, project_dir)?;
    let mut updated = Vec::new();
    let candidates = manifest.skills.clone();
    for existing in candidates {
        if !args.skills.is_empty()
            && !args
                .skills
                .iter()
                .any(|requested| requested == &existing.name || requested == &existing.id)
        {
            continue;
        }
        let source = resolve_source(&existing.source).await?;
        let discovered = discover_skills(&source.root)?;
        let skill = discovered
            .iter()
            .find(|candidate| candidate.name == existing.name)
            .ok_or_else(|| {
                LpmError::Registry(format!(
                    "source `{}` no longer contains skill `{}`",
                    existing.source, existing.name
                ))
            })?;
        let audit = audit_skill(skill)?;
        if !audit.findings.is_empty() {
            return Err(LpmError::Registry(format!(
                "refusing update of `{}` due to blocked findings: {}",
                existing.name,
                audit.findings.join(", ")
            )));
        }
        if audit.digest == existing.digest {
            continue;
        }
        if !args.yes && !is_interactive(false, json_output) {
            return Err(LpmError::Registry(
                "pass `--yes` when updating skills without an interactive terminal".into(),
            ));
        }
        if !args.yes && is_interactive(false, json_output) {
            let confirmed = cliclack::confirm(format!("Update {}?", existing.name))
                .initial_value(true)
                .interact()
                .map_err(prompt_err)?;
            if !confirmed {
                continue;
            }
        }
        let mut next_manifest = manifest.clone();
        next_manifest
            .skills
            .retain(|managed| managed.id != existing.id);
        let audit_ref = [(skill, audit.clone())];
        preflight_install(
            &next_manifest,
            &audit_ref,
            &existing.bindings,
            scope,
            project_dir,
        )?;
        let updated_skill = install_skill(
            &mut next_manifest,
            skill,
            &audit,
            InstallOptions {
                source: &source.source,
                source_kind: source.source_kind,
                resolved_revision: source.resolved_revision.as_deref(),
                scope,
                bindings: &existing.bindings,
                project_dir,
            },
        )?;
        if let Err(error) = next_manifest.save(scope, project_dir) {
            let _ = remove_managed_skill(&updated_skill, project_dir);
            return Err(error);
        }
        // The replacement is fully materialized and persisted before the prior
        // generation is retired, so a failed refresh never destroys a usable skill.
        remove_managed_skill(&existing, project_dir)?;
        manifest = next_manifest;
        updated.push(updated_skill.name);
    }
    if json_output {
        print_json(serde_json::json!({
            "success": true,
            "action": "update",
            "updated": updated,
            "count": updated.len(),
        }));
    } else if updated.is_empty() {
        install_ui::done("All managed skills are current");
    } else {
        install_ui::done(&format!(
            "Updated {} {}",
            updated.len(),
            plural(updated.len(), "skill")
        ));
    }
    Ok(())
}

fn run_doctor(
    args: SkillsScopeArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let skills = load_scoped_skills(args, project_dir)?;
    let mut checks = Vec::new();
    for skill in skills {
        let canonical = managed_root(skill.scope, project_dir)?.join(&skill.id);
        checks.push(serde_json::json!({
            "code": "managed_content",
            "skill": skill.name,
            "passed": canonical.join("SKILL.md").is_file(),
            "path": canonical,
        }));
        for binding in &skill.bindings {
            let target = binding
                .agent
                .skill_root(skill.scope, project_dir)?
                .join(&skill.id);
            checks.push(serde_json::json!({
                "code": "agent_visibility",
                "skill": skill.name,
                "agent": binding.agent.as_str(),
                "enabled": binding.enabled,
                "passed": !binding.enabled || target.symlink_metadata().is_ok(),
                "path": target,
            }));
        }
    }
    let failures = checks
        .iter()
        .filter(|check| check["passed"] == false)
        .count();
    if json_output {
        print_json(serde_json::json!({
            "success": failures == 0,
            "checks": checks,
            "count": checks.len(),
            "failures": failures,
        }));
    } else if checks.is_empty() {
        install_ui::warn("No managed skills installed");
    } else {
        for check in &checks {
            let passed = check["passed"].as_bool().unwrap_or(false);
            let status = if passed { "healthy" } else { "broken" };
            eprintln!(
                "  {} {}  {}",
                install_ui::bullet(passed),
                check["skill"].as_str().unwrap_or_default(),
                if passed {
                    install_ui::status_ok(status)
                } else {
                    status.red()
                }
            );
        }
        if failures == 0 {
            install_ui::done("All managed skill checks passed");
        } else {
            install_ui::warn(&format!("{failures} skill checks need attention"));
        }
    }
    if json_output || failures == 0 {
        Ok(())
    } else {
        Err(LpmError::Registry(
            "managed skill health checks failed".into(),
        ))
    }
}

fn run_validate(
    args: SkillsValidateArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match args.path {
        Some(path) => run_standard_validate(Path::new(&path), json_output),
        None => run_package_validate(project_dir, json_output),
    }
}

fn run_standard_validate(path: &Path, json_output: bool) -> Result<(), LpmError> {
    let root = std::fs::canonicalize(path).map_err(LpmError::Io)?;
    let skills = discover_skills(&root)?;
    let audits: Vec<_> = skills
        .iter()
        .map(|skill| audit_skill(skill).map(|audit| (skill, audit)))
        .collect::<Result<_, _>>()?;
    let findings = audits
        .iter()
        .map(|(_, audit)| audit.findings.len())
        .sum::<usize>();
    if json_output {
        print_json(serde_json::json!({
            "success": findings == 0,
            "skills": audits.iter().map(|(skill, audit)| serde_json::json!({
                "name": skill.name,
                "description": skill.description,
                "size_bytes": audit.size_bytes,
                "estimated_tokens": audit.estimated_tokens,
                "findings": audit.findings,
            })).collect::<Vec<_>>(),
            "count": audits.len(),
            "findings_count": findings,
        }));
    } else if findings == 0 {
        install_ui::done(&format!(
            "Validated {} {}",
            audits.len(),
            plural(audits.len(), "skill")
        ));
    } else {
        return Err(LpmError::Registry(format!(
            "{findings} blocked skill validation findings"
        )));
    }
    Ok(())
}

fn run_package_validate(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let root = project_dir.join(".lpm").join("skills");
    let packages = match std::fs::read_dir(&root) {
        Ok(packages) => packages,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if json_output {
                print_json(serde_json::json!({
                    "success": true,
                    "valid": 0,
                    "errors": [],
                    "quality_impact": 0,
                }));
            } else {
                install_ui::warn("No package-published skills installed");
            }
            return Ok(());
        }
        Err(error) => return Err(LpmError::Io(error)),
    };

    let mut errors = Vec::new();
    let mut valid = 0usize;
    let mut total_size = 0u64;
    for package in packages {
        let package = package.map_err(LpmError::Io)?;
        let package_path = package.path();
        if !package_path.is_dir() {
            continue;
        }
        let package_name = package.file_name().to_string_lossy().to_string();
        for skill in std::fs::read_dir(&package_path).map_err(LpmError::Io)? {
            let skill = skill.map_err(LpmError::Io)?;
            let path = skill.path();
            if path.extension().is_none_or(|extension| extension != "md") {
                continue;
            }
            let skill_name = path
                .file_stem()
                .map(|name| name.to_string_lossy())
                .unwrap_or_default();
            let display_name = format!("{package_name}/{skill_name}");
            let size = skill.metadata().map_err(LpmError::Io)?.len();
            total_size = total_size.saturating_add(size);
            if size > 15 * 1024 {
                errors.push(format!("{display_name}: exceeds 15KB limit ({size} bytes)"));
                continue;
            }
            let content = std::fs::read_to_string(&path).map_err(LpmError::Io)?;
            if content.len() < 100 {
                errors.push(format!(
                    "{display_name}: content too short (need 100+ chars)"
                ));
                continue;
            }
            if !content.starts_with("---") {
                errors.push(format!("{display_name}: missing YAML frontmatter"));
                continue;
            }
            valid += 1;
        }
    }
    if total_size > 100 * 1024 {
        errors.push(format!(
            "total skills size {total_size} bytes exceeds 100KB limit"
        ));
    }

    let quality_impact = if valid >= 3 {
        10
    } else if valid > 0 {
        7
    } else {
        0
    };
    if json_output {
        print_json(serde_json::json!({
            "success": errors.is_empty(),
            "valid": valid,
            "errors": errors,
            "quality_impact": quality_impact,
        }));
        return if errors.is_empty() {
            Ok(())
        } else {
            Err(LpmError::ExitCode(1))
        };
    }
    if errors.is_empty() {
        install_ui::done(&format!(
            "Validated {valid} package-published {}",
            plural(valid, "skill")
        ));
        return Ok(());
    }
    for error in &errors {
        install_ui::warn(error);
    }
    Err(LpmError::Script(format!(
        "{} package skill validation error(s)",
        errors.len()
    )))
}

fn mutation_scope(args: SkillsScopeArgs, _project_dir: &Path) -> SkillScope {
    if args.global {
        SkillScope::Global
    } else {
        SkillScope::Project
    }
}

fn load_scoped_skills(
    args: SkillsScopeArgs,
    project_dir: &Path,
) -> Result<Vec<ManagedSkill>, LpmError> {
    let scopes: &[SkillScope] = if args.project {
        &[SkillScope::Project]
    } else if args.global {
        &[SkillScope::Global]
    } else {
        &[SkillScope::Project, SkillScope::Global]
    };
    let mut skills = Vec::new();
    for scope in scopes {
        skills.extend(SkillManifest::load(*scope, project_dir)?.skills);
    }
    skills.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(skills)
}

fn load_skill_inventory(
    args: SkillsScopeArgs,
    project_dir: &Path,
) -> Result<Vec<ManagedSkill>, LpmError> {
    let scopes: &[SkillScope] = if args.project {
        &[SkillScope::Project]
    } else if args.global {
        &[SkillScope::Global]
    } else {
        &[SkillScope::Project, SkillScope::Global]
    };
    skills_inventory::load(scopes, project_dir)
}

fn parse_agents(agents: &[String]) -> Result<Vec<AgentTarget>, LpmError> {
    let parsed: Vec<_> = agents
        .iter()
        .map(|agent| AgentTarget::parse(agent))
        .collect::<Result<_, _>>()?;
    if parsed
        .iter()
        .enumerate()
        .any(|(index, agent)| parsed[..index].contains(agent))
    {
        return Err(LpmError::Registry(
            "each agent may be specified only once".into(),
        ));
    }
    Ok(parsed)
}

fn skill_is_selected(skill: &ManagedSkill, requested: &[String], all: bool) -> bool {
    all || requested
        .iter()
        .any(|name| name == &skill.name || name == &skill.id)
}

fn preflight_remove_skill(skill: &ManagedSkill, project_dir: &Path) -> Result<(), LpmError> {
    let canonical = managed_root(skill.scope, project_dir)?.join(&skill.id);
    for binding in &skill.bindings {
        let target = binding
            .agent
            .skill_root(skill.scope, project_dir)?
            .join(&skill.id);
        validate_owned_target(&target, &canonical, binding.copied, &skill.id)?;
    }
    Ok(())
}

fn remove_managed_skill(skill: &ManagedSkill, project_dir: &Path) -> Result<(), LpmError> {
    let canonical = managed_root(skill.scope, project_dir)?.join(&skill.id);
    for binding in &skill.bindings {
        let target = binding
            .agent
            .skill_root(skill.scope, project_dir)?
            .join(&skill.id);
        remove_owned_target(&target, &canonical, binding.copied, &skill.id)?;
    }
    if canonical.exists() {
        std::fs::remove_dir_all(canonical).map_err(LpmError::Io)?;
    }
    Ok(())
}

fn remove_owned_target(
    path: &Path,
    canonical: &Path,
    copied: bool,
    id: &str,
) -> Result<(), LpmError> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    validate_owned_target(path, canonical, copied, id)?;
    if metadata.file_type().is_symlink() {
        std::fs::remove_file(path).map_err(LpmError::Io)
    } else if metadata.is_dir() && copied {
        std::fs::remove_dir_all(path).map_err(LpmError::Io)
    } else {
        Err(LpmError::Registry(format!(
            "refusing to remove unsupported managed skill path {}",
            path.display()
        )))
    }
}

fn validate_owned_target(
    path: &Path,
    canonical: &Path,
    copied: bool,
    id: &str,
) -> Result<(), LpmError> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(LpmError::Io(error)),
    };
    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(path).map_err(LpmError::Io)?;
        let target = if target.is_absolute() {
            target
        } else {
            path.parent().unwrap_or_else(|| Path::new(".")).join(target)
        };
        if target != canonical {
            return Err(LpmError::Registry(format!(
                "refusing to remove agent skill path {} because it no longer points to LPM-managed content",
                path.display()
            )));
        }
        return Ok(());
    }
    if metadata.is_dir() && copied {
        let marker = path.join(".lpm-skill-owner");
        let owner = std::fs::read_to_string(&marker).map_err(|_| {
            LpmError::Registry(format!(
                "refusing to remove agent skill path {} because it is not an LPM-managed copy",
                path.display()
            ))
        })?;
        if owner.trim() == id {
            return Ok(());
        }
        return Err(LpmError::Registry(format!(
            "refusing to remove agent skill path {} because its ownership marker does not match",
            path.display()
        )));
    }
    Err(LpmError::Registry(format!(
        "refusing to remove unsupported managed skill path {}",
        path.display()
    )))
}

fn print_skill_rows(skills: &[ManagedSkill]) {
    let width = skills
        .iter()
        .map(|skill| skill.name.len())
        .max()
        .unwrap_or(0);
    for skill in skills {
        let bindings = skill
            .bindings
            .iter()
            .map(|binding| {
                format!(
                    "{} {}",
                    install_ui::bullet(binding.enabled),
                    binding.agent.display_name()
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!(
            "  {:<width$}  {}  {}  {}",
            skill.name,
            install_ui::cyan(skill.scope.as_str()),
            skill_ownership(skill).dimmed(),
            bindings.dimmed()
        );
    }
}

fn print_skill_view(skill: &ManagedSkill, project_dir: &Path) -> Result<(), LpmError> {
    eprintln!("{}", install_ui::section(&skill.name));
    eprintln!("  {}  {}", "description".dimmed(), skill.description);
    eprintln!(
        "  {}       {}",
        "source".dimmed(),
        install_ui::cyan(&skill.source)
    );
    if let Some(revision) = &skill.resolved_revision {
        eprintln!("  {}     {}", "revision".dimmed(), revision.dimmed());
    }
    eprintln!(
        "  {}        {}",
        "scope".dimmed(),
        install_ui::cyan(skill.scope.as_str())
    );
    eprintln!(
        "  {}    {}",
        "ownership".dimmed(),
        skill_ownership(skill).dimmed()
    );
    eprintln!(
        "  {}       ~{} tokens · {}",
        "context".dimmed(),
        skill.estimated_tokens,
        lpm_common::format_bytes(skill.size_bytes).dimmed()
    );
    for binding in &skill.bindings {
        let visible = binding.enabled
            && agent_visible_path(binding.agent, skill.scope, project_dir, &skill.id)?.is_some();
        eprintln!(
            "  {}       {} {}  {}",
            "agent".dimmed(),
            install_ui::bullet(visible),
            binding.agent.display_name(),
            if visible {
                install_ui::status_ok("visible")
            } else {
                "not visible".red()
            }
        );
    }
    Ok(())
}

fn skill_json(skill: &ManagedSkill) -> serde_json::Value {
    serde_json::json!({
        "id": skill.id,
        "name": skill.name,
        "description": skill.description,
        "source": skill.source,
        "source_kind": skill.source_kind,
        "ownership": skill_ownership(skill),
        "resolved_revision": skill.resolved_revision,
        "scope": skill.scope.as_str(),
        "enabled": skill.bindings.iter().any(|binding| binding.enabled),
        "agents": skill.bindings.iter().map(|binding| serde_json::json!({
            "name": binding.agent.as_str(),
            "enabled": binding.enabled,
            "copied": binding.copied,
        })).collect::<Vec<_>>(),
        "estimated_tokens": skill.estimated_tokens,
        "size_bytes": skill.size_bytes,
    })
}

fn skill_view_json(skill: &ManagedSkill, project_dir: &Path) -> serde_json::Value {
    let mut value = skill_json(skill);
    let bindings = skill
        .bindings
        .iter()
        .map(|binding| {
            let path = agent_visible_path(binding.agent, skill.scope, project_dir, &skill.id);
            serde_json::json!({
                "name": binding.agent.as_str(),
                "enabled": binding.enabled,
                "visible": binding.enabled && path.as_ref().is_ok_and(Option::is_some),
                "path": path.ok().flatten().map(|path| path.display().to_string()).unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    value["agents"] = serde_json::Value::Array(bindings);
    value["digest"] = serde_json::Value::String(skill.digest.clone());
    value
}

fn skill_ownership(skill: &ManagedSkill) -> &'static str {
    match skill.source_kind.as_str() {
        "external" => "external",
        "package" => "package",
        _ => "managed",
    }
}

fn agent_visible_path(
    agent: AgentTarget,
    scope: SkillScope,
    project_dir: &Path,
    id: &str,
) -> Result<Option<PathBuf>, LpmError> {
    for root in agent.inventory_roots(scope, project_dir)? {
        let path = root.join(id);
        if path.symlink_metadata().is_ok() {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn managed_id(name: &str, digest: &str) -> String {
    let suffix = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("{name}--{}", &suffix[..12.min(suffix.len())])
}

fn print_json(value: serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(&value).unwrap());
}

fn is_interactive(yes: bool, json_output: bool) -> bool {
    !yes && !json_output && std::io::stdin().is_terminal()
}

fn plural(count: usize, singular: &str) -> String {
    if count == 1 {
        singular.to_string()
    } else {
        format!("{singular}s")
    }
}

fn count_files_recursive(directory: &Path) -> Result<usize, std::io::Error> {
    let mut count = 0usize;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            count += count_files_recursive(&entry.path())?;
        } else {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_id_uses_skill_name_and_digest_prefix() {
        assert_eq!(
            managed_id("find-skills", "sha256:0123456789abcdef"),
            "find-skills--0123456789ab"
        );
    }

    #[test]
    fn mutation_scope_defaults_to_project() {
        let project = tempfile::tempdir().unwrap();
        let scope = mutation_scope(
            SkillsScopeArgs {
                global: false,
                project: false,
            },
            project.path(),
        );
        assert_eq!(scope, SkillScope::Project);
    }
}
