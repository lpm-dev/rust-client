//! Unified management for package-published and standalone agent skills.
//!
//! Package-published skills remain in `.lpm/skills/<package>/`. Standalone
//! skills have a separate LPM-managed store and are explicitly materialized
//! into supported agent directories.

mod managed;
mod source;

use crate::install_ui;
use clap::{Args, Subcommand, ValueEnum};
use lpm_common::LpmError;
use lpm_common::color::Painted;
use lpm_registry::RegistryClient;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::Path;

#[derive(Debug, Subcommand)]
pub enum SkillsCmd {
    /// Add a package-published LPM.dev skill set or a standalone agent skill.
    Add(AddArgs),
    /// List package-published, LPM-managed, and externally discovered skills.
    #[command(visible_alias = "ls")]
    List(ListArgs),
    /// Show source, security, context, and agent-target details for a skill.
    View(ViewArgs),
    /// Validate package-published `.lpm/skills/` files against publishing rules.
    Validate,
    /// Remove package-published `.lpm/skills/` content.
    Clean,
    /// Diagnose managed agent targets and externally discovered broken links.
    Doctor(DoctorArgs),
    /// Resolve managed standalone sources again and preview their changes.
    Update(ManageArgs),
    /// Remove managed standalone skills and their agent targets.
    #[command(visible_alias = "rm")]
    Remove(ManageArgs),
    /// Restore managed standalone skills to their recorded agent targets.
    Enable(ManageArgs),
    /// Remove managed standalone skills from agent targets without deleting their store content.
    Disable(ManageArgs),
    /// Remove stale managed targets and records after a preview and confirmation.
    Prune(PruneArgs),
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// `@lpm.dev/owner.package`, a GitHub URL or `owner/repo`, or a local skill directory.
    #[arg(value_name = "SOURCE")]
    pub source: Option<String>,
    /// Select a standalone skill by name. Repeat or use `*` for every discovered skill.
    #[arg(long, value_name = "NAME")]
    pub skill: Vec<String>,
    /// Select a standalone agent target. Repeat for each target.
    #[arg(long, value_enum, value_name = "AGENT")]
    pub agent: Vec<AgentTarget>,
    /// Store standalone skills in this project.
    #[arg(long, conflicts_with = "global")]
    pub project: bool,
    /// Store standalone skills under the LPM home directory.
    #[arg(long, conflicts_with = "project")]
    pub global: bool,
    /// Copy standalone files into agent directories instead of linking them.
    #[arg(long)]
    pub copy: bool,
    /// Discover and preview skills without installing them.
    #[arg(long)]
    pub list: bool,
    /// Search outside the standard skill locations in a standalone source.
    #[arg(long)]
    pub full_depth: bool,
    /// Print every planned filesystem change without mutating it.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm a non-interactive mutation.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args, Default)]
pub struct ListArgs {
    /// Include global managed and external skill locations.
    #[arg(long)]
    pub global: bool,
    /// Restrict the inventory to a category.
    #[arg(long, value_enum)]
    pub kind: Option<SkillKind>,
    /// Restrict managed and external results to an agent target.
    #[arg(long, value_enum)]
    pub agent: Option<AgentTarget>,
}

#[derive(Debug, Args)]
pub struct ViewArgs {
    /// Managed skill name, package name, or `package/skill` selector.
    #[arg(value_name = "SELECTOR")]
    pub selector: String,
    /// Include global managed and external skill locations when looking up the selector.
    #[arg(long)]
    pub global: bool,
}

#[derive(Debug, Args, Default)]
pub struct DoctorArgs {
    /// Include global managed and external skill locations.
    #[arg(long)]
    pub global: bool,
}

#[derive(Debug, Args, Default)]
pub struct ManageArgs {
    /// Managed skill names. Omit only with `--all` in a TTY.
    #[arg(value_name = "SKILL")]
    pub selectors: Vec<String>,
    /// Restrict the operation to these agent targets.
    #[arg(long, value_enum, value_name = "AGENT")]
    pub agent: Vec<AgentTarget>,
    /// Operate on global managed skills instead of the current project.
    #[arg(long)]
    pub global: bool,
    /// Select every managed skill in the chosen scope.
    #[arg(long)]
    pub all: bool,
    /// Print the mutation plan without applying it.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm a non-interactive mutation.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args, Default)]
pub struct PruneArgs {
    /// Prune global managed state instead of project-managed state.
    #[arg(long)]
    pub global: bool,
    /// Print the stale targets and records without applying the cleanup.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm a non-interactive mutation.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(
    Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum AgentTarget {
    Codex,
    ClaudeCode,
    Cursor,
}

impl AgentTarget {
    const ALL: [Self; 3] = [Self::Codex, Self::ClaudeCode, Self::Cursor];

    fn label(self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::ClaudeCode => "Claude Code",
            Self::Cursor => "Cursor",
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum SkillKind {
    Package,
    Managed,
    External,
}

pub async fn run(
    client: &RegistryClient,
    action: SkillsCmd,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    match action {
        SkillsCmd::Add(args) => run_add(client, args, project_dir, json_output).await,
        SkillsCmd::List(args) => list_skills(project_dir, &args, json_output),
        SkillsCmd::View(args) => view_skill(project_dir, &args, json_output),
        SkillsCmd::Validate => validate_skills(project_dir, json_output),
        SkillsCmd::Clean => clean_skills(project_dir, json_output),
        SkillsCmd::Doctor(args) => managed::doctor(project_dir, args.global, json_output),
        SkillsCmd::Update(args) => managed::update(project_dir, args, json_output).await,
        SkillsCmd::Remove(args) => {
            managed::mutate(project_dir, args, managed::Mutation::Remove, json_output)
        }
        SkillsCmd::Enable(args) => {
            managed::mutate(project_dir, args, managed::Mutation::Enable, json_output)
        }
        SkillsCmd::Disable(args) => {
            managed::mutate(project_dir, args, managed::Mutation::Disable, json_output)
        }
        SkillsCmd::Prune(args) => managed::prune(project_dir, args, json_output),
    }
}

async fn run_add(
    client: &RegistryClient,
    mut args: AddArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    let source_input = prompt_for_source(args.source.take(), json_output)?;
    if source_input.starts_with("@lpm.dev/") {
        return add_package_skills(client, &source_input, &args, project_dir, json_output).await;
    }

    let tree = source::load(&source_input, project_dir).await?;
    let discovered = source::discover(&tree, args.full_depth)?;
    if args.list {
        print_discovery(&tree, &discovered, json_output);
        return Ok(());
    }

    let selected = select_skills(&args.skill, &discovered, json_output)?;
    let scope = choose_scope(args.project, args.global, json_output)?;
    let agents = choose_agents(&args.agent, json_output)?;
    source::ensure_agents_are_compatible(&selected, &agents)?;

    let store = managed::Store::for_scope(scope, project_dir)?;
    let plan = managed::plan_install(&store, &tree, &selected, &agents, args.copy)?;
    if args.dry_run || !json_output {
        print_standalone_plan(&tree, &selected, &plan, json_output);
    }
    if args.dry_run {
        return Ok(());
    }
    source::ensure_skills_are_safe(&selected)?;
    require_confirmation(
        args.yes,
        json_output,
        "Install the planned standalone skills?",
    )?;
    let changes = plan.changes.clone();
    managed::apply_install(&store, &tree, &selected, plan)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "kind": "managed",
                "installed": selected.iter().map(|skill| skill.name.as_str()).collect::<Vec<_>>(),
                "scope": scope.as_str(),
                "agents": agents.iter().map(|agent| agent.slug()).collect::<Vec<_>>(),
                "source": tree.descriptor,
                "skills": selected.iter().map(|skill| skill.json()).collect::<Vec<_>>(),
                "changes": changes,
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!(
            "Installed {} managed {} for {}",
            selected.len(),
            plural(selected.len(), "skill", "skills"),
            agents
                .iter()
                .map(|agent| agent.label())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    Ok(())
}

fn prompt_for_source(source: Option<String>, json_output: bool) -> Result<String, LpmError> {
    if let Some(source) = source {
        return Ok(source);
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "a source is required outside a TTY; pass `lpm skills add <source>`".into(),
        ));
    }
    let kind: &str = cliclack::select("What kind of skill source do you want to add?")
        .item("package", "LPM.dev package", "@lpm.dev/owner.package")
        .item(
            "standalone",
            "GitHub or local skill directory",
            "owner/repo, HTTPS URL, or path",
        )
        .initial_value("standalone")
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    let placeholder = if kind == "package" {
        "@lpm.dev/owner.package"
    } else {
        "owner/repo, https://github.com/owner/repo, or ./skills"
    };
    let source: String = cliclack::input("Source")
        .placeholder(placeholder)
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    let source = source.trim();
    if source.is_empty() {
        return Err(LpmError::Registry("a skill source is required".into()));
    }
    if kind == "package" && !source.starts_with("@lpm.dev/") {
        return Err(LpmError::Registry(
            "LPM.dev package sources must start with `@lpm.dev/`".into(),
        ));
    }
    Ok(source.to_string())
}

async fn add_package_skills(
    client: &RegistryClient,
    package: &str,
    args: &AddArgs,
    project_dir: &Path,
    json_output: bool,
) -> Result<(), LpmError> {
    if !args.skill.is_empty() || !args.agent.is_empty() || args.project || args.global || args.copy
    {
        return Err(LpmError::Registry(
            "`--skill`, `--agent`, scope, and `--copy` apply only to standalone skills; package-published skills are materialized as one package-owned set".into(),
        ));
    }
    let name = lpm_common::PackageName::parse(package)?;
    let response = client.get_skills(&name.short(), None).await?;
    let target = project_dir.join(".lpm").join("skills").join(name.short());
    let skills: Vec<_> = response
        .skills
        .iter()
        .filter(|skill| {
            lpm_common::is_safe_skill_name(&skill.name)
                && skill
                    .raw_content
                    .as_deref()
                    .or(skill.content.as_deref())
                    .is_some_and(|content| !content.is_empty())
        })
        .collect();

    if args.list || args.dry_run {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "success": true,
                    "kind": "package",
                    "package": name.scoped(),
                    "directory": target,
                    "skills": skills.iter().map(|skill| serde_json::json!({
                        "name": skill.name,
                        "description": skill.description,
                        "size": skill.size_bytes,
                    })).collect::<Vec<_>>(),
                    "dry_run": args.dry_run,
                }))
                .unwrap()
            );
        } else {
            println!("{}", name.scoped().cyan());
            for skill in &skills {
                println!("  {}", skill.name);
            }
            install_ui::phase(&format!("would materialize {}", target.display()));
        }
        return Ok(());
    }
    require_confirmation(
        args.yes,
        json_output,
        "Materialize these package-published skills?",
    )?;
    std::fs::create_dir_all(&target)?;
    let mut installed = 0usize;
    for skill in skills {
        let Some(content) = skill.raw_content.as_deref().or(skill.content.as_deref()) else {
            continue;
        };
        std::fs::write(target.join(format!("{}.md", skill.name)), content)?;
        installed += 1;
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "kind": "package",
                "package": name.scoped(),
                "installed": installed,
                "directory": target,
            }))
            .unwrap()
        );
    } else {
        install_ui::done(&format!(
            "Materialized {installed} package-published {}",
            plural(installed, "skill", "skills")
        ));
        eprintln!("  {}", target.display().to_string().dimmed());
    }
    Ok(())
}

fn select_skills<'a>(
    requested: &[String],
    discovered: &'a [source::DiscoveredSkill],
    json_output: bool,
) -> Result<Vec<&'a source::DiscoveredSkill>, LpmError> {
    if discovered.is_empty() {
        return Err(LpmError::Registry(
            "no standard SKILL.md skills found".into(),
        ));
    }
    if requested.iter().any(|name| name == "*") {
        return Ok(discovered.iter().collect());
    }
    if !requested.is_empty() {
        let wanted: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
        let selected: Vec<_> = discovered
            .iter()
            .filter(|skill| wanted.contains(skill.name.as_str()))
            .collect();
        if selected.len() != wanted.len() {
            let available = discovered
                .iter()
                .map(|skill| skill.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(LpmError::Registry(format!(
                "requested skill was not discovered; available: {available}"
            )));
        }
        return Ok(selected);
    }
    if discovered.len() == 1 {
        return Ok(vec![&discovered[0]]);
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "multiple skills were discovered; pass `--skill <name>` or `--skill '*'`".into(),
        ));
    }
    let mut prompt = cliclack::multiselect("Select skills  (space=toggle  a=all  enter=confirm)");
    for skill in discovered {
        prompt = prompt.item(
            skill.name.clone(),
            skill.name.clone(),
            format!("{} · ~{} tokens", skill.description, skill.context_tokens),
        );
    }
    let selected_names: Vec<String> = prompt.interact().map_err(crate::prompt::prompt_err)?;
    if selected_names.is_empty() {
        return Err(LpmError::Registry("no skills selected".into()));
    }
    let selected_names: BTreeSet<_> = selected_names.into_iter().collect();
    Ok(discovered
        .iter()
        .filter(|skill| selected_names.contains(&skill.name))
        .collect())
}

fn choose_scope(
    project: bool,
    global: bool,
    json_output: bool,
) -> Result<managed::Scope, LpmError> {
    if project {
        return Ok(managed::Scope::Project);
    }
    if global {
        return Ok(managed::Scope::Global);
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "standalone installs outside a TTY require `--project` or `--global`".into(),
        ));
    }
    let choice: &str = cliclack::select("Install scope")
        .item("project", "Project", "shared in this repository")
        .item("global", "Global", "available across projects")
        .initial_value("project")
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    Ok(if choice == "global" {
        managed::Scope::Global
    } else {
        managed::Scope::Project
    })
}

fn choose_agents(
    requested: &[AgentTarget],
    json_output: bool,
) -> Result<Vec<AgentTarget>, LpmError> {
    if !requested.is_empty() {
        return Ok(requested.to_vec());
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "standalone installs outside a TTY require at least one `--agent`".into(),
        ));
    }
    let mut prompt = cliclack::multiselect("Install for agents  (space=toggle  enter=confirm)");
    for agent in AgentTarget::ALL {
        prompt = prompt.item(agent, agent.label(), "standard Agent Skills location");
    }
    let agents: Vec<AgentTarget> = prompt
        .initial_values(vec![AgentTarget::Codex])
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    if agents.is_empty() {
        return Err(LpmError::Registry("no agent targets selected".into()));
    }
    Ok(agents)
}

fn require_confirmation(yes: bool, json_output: bool, prompt: &str) -> Result<(), LpmError> {
    if yes {
        return Ok(());
    }
    if !is_interactive(json_output) {
        return Err(LpmError::Registry(
            "non-interactive mutation requires `--yes` after reviewing `--dry-run`".into(),
        ));
    }
    let confirmed = cliclack::confirm(prompt)
        .initial_value(false)
        .interact()
        .map_err(crate::prompt::prompt_err)?;
    if confirmed {
        Ok(())
    } else {
        Err(LpmError::Script(
            "skill operation cancelled; no files changed".into(),
        ))
    }
}

fn is_interactive(json_output: bool) -> bool {
    !json_output && std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

fn print_discovery(
    tree: &source::SourceTree,
    discovered: &[source::DiscoveredSkill],
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "source": tree.descriptor,
                "skills": discovered.iter().map(|skill| skill.json()).collect::<Vec<_>>(),
            }))
            .unwrap()
        );
    } else {
        for skill in discovered {
            println!(
                "{}  {} · ~{} tokens",
                skill.name,
                skill.description.dimmed(),
                skill.context_tokens
            );
            if !skill.findings.is_empty() {
                println!(
                    "  {} {} security finding(s)",
                    "!".yellow(),
                    skill.findings.len()
                );
            }
        }
    }
}

fn print_standalone_plan(
    tree: &source::SourceTree,
    selected: &[&source::DiscoveredSkill],
    plan: &managed::InstallPlan,
    json_output: bool,
) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "dry_run": true,
                "source": tree.descriptor,
                "skills": selected.iter().map(|skill| skill.json()).collect::<Vec<_>>(),
                "changes": plan.changes,
            }))
            .unwrap()
        );
        return;
    }
    install_ui::phase(&format!("Source: {}", tree.descriptor.display()));
    for skill in selected {
        println!(
            "  {}  {}",
            skill.name.yellow(),
            format!("~{} tokens", skill.context_tokens).dimmed()
        );
        for finding in &skill.findings {
            println!(
                "    {} {} at {}:{}",
                "!".yellow(),
                finding.category,
                finding.path,
                finding.line
            );
        }
    }
    install_ui::phase("Planned filesystem changes:");
    for change in &plan.changes {
        println!("  {} {}", change.action, change.path.display());
    }
}

fn list_skills(project_dir: &Path, args: &ListArgs, json_output: bool) -> Result<(), LpmError> {
    let packages = package_inventory(project_dir)?;
    let managed = managed::inventory(project_dir, args.global)?;
    let external = managed::external_inventory(project_dir, args.global)?;
    let kind_matches = |kind| args.kind.is_none_or(|wanted| wanted == kind);
    let managed: Vec<_> = managed
        .into_iter()
        .filter(|item| {
            kind_matches(SkillKind::Managed)
                && args.agent.is_none_or(|agent| item.agents.contains(&agent))
        })
        .collect();
    let external: Vec<_> = external
        .into_iter()
        .filter(|item| {
            kind_matches(SkillKind::External) && args.agent.is_none_or(|agent| item.agent == agent)
        })
        .collect();
    let packages: Vec<_> = if kind_matches(SkillKind::Package) {
        packages
    } else {
        Vec::new()
    };

    if json_output {
        let mut map = serde_json::Map::new();
        map.insert("success".into(), serde_json::Value::Bool(true));
        for (package, skills) in &packages {
            map.insert(
                package.clone(),
                serde_json::Value::Array(
                    skills
                        .iter()
                        .map(|(name, size)| serde_json::json!({"name": name, "size": size}))
                        .collect(),
                ),
            );
        }
        map.insert(
            "skills".into(),
            serde_json::json!({
                "package": packages.iter().flat_map(|(package, skills)| skills.iter().map(move |(name, size)| serde_json::json!({"package": package, "name": name, "size": size}))).collect::<Vec<_>>(),
                "managed": managed,
                "external": external,
            }),
        );
        println!("{}", serde_json::to_string_pretty(&map).unwrap());
        return Ok(());
    }

    if !packages.is_empty() {
        print_package_inventory(&packages);
    }
    if !managed.is_empty() {
        println!("{}", "managed".yellow().bold());
        for skill in &managed {
            println!("  {:<24} {}", skill.name, skill.summary().dimmed());
        }
        println!();
    }
    if !external.is_empty() {
        println!("{}", "external".yellow().bold());
        for skill in &external {
            println!("  {:<24} {}", skill.name, skill.summary().dimmed());
        }
        println!();
    }
    let package_total: usize = packages.iter().map(|(_, skills)| skills.len()).sum();
    let total = package_total + managed.len() + external.len();
    if total == 0 {
        install_ui::warn("No skills installed or discovered");
    } else if managed.is_empty() && external.is_empty() {
        install_ui::done(&format!(
            "{package_total} {} installed across {} {}",
            plural(package_total, "skill", "skills"),
            packages.len(),
            plural(packages.len(), "package", "packages"),
        ));
    } else {
        install_ui::done(&format!("{total} skills in the unified inventory"));
    }
    Ok(())
}

fn view_skill(project_dir: &Path, args: &ViewArgs, json_output: bool) -> Result<(), LpmError> {
    let packages = package_inventory(project_dir)?;
    if let Some((package, skill)) = args.selector.split_once('/')
        && let Some((_, skills)) = packages.iter().find(|(name, _)| name == package)
        && let Some((name, size)) = skills.iter().find(|(name, _)| name == skill)
    {
        print_package_view(package, name, *size, json_output);
        return Ok(());
    }
    if let Some((package, skills)) = packages.iter().find(|(name, _)| *name == args.selector)
        && skills.len() == 1
    {
        print_package_view(package, &skills[0].0, skills[0].1, json_output);
        return Ok(());
    }
    managed::view(project_dir, &args.selector, args.global, json_output)
}

fn print_package_view(package: &str, name: &str, size: u64, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "kind": "package",
                "package": format!("@lpm.dev/{package}"),
                "name": name,
                "size": size,
            }))
            .unwrap()
        );
    } else {
        println!("{}", format!("@lpm.dev/{package}/{name}").cyan());
        println!("  kind: package-published");
        println!("  size: {}", lpm_common::format_bytes(size));
        println!("  path: .lpm/skills/{package}/{name}.md");
    }
}

type PackageSkills = Vec<(String, u64)>;
type PackageInventory = Vec<(String, PackageSkills)>;

fn package_inventory(project_dir: &Path) -> Result<PackageInventory, LpmError> {
    let skills_dir = project_dir.join(".lpm").join("skills");
    let mut packages = Vec::new();
    let entries = match std::fs::read_dir(skills_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(packages),
        Err(error) => return Err(LpmError::Io(error)),
    };
    for package in entries.flatten() {
        if !package.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let mut skills = Vec::new();
        for skill in std::fs::read_dir(package.path())?.flatten() {
            let path = skill.path();
            if path.extension().is_some_and(|extension| extension == "md") {
                skills.push((
                    path.file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    skill.metadata().map_or(0, |metadata| metadata.len()),
                ));
            }
        }
        skills.sort_by(|left, right| left.0.cmp(&right.0));
        if !skills.is_empty() {
            packages.push((package.file_name().to_string_lossy().to_string(), skills));
        }
    }
    packages.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(packages)
}

fn print_package_inventory(packages: &[(String, Vec<(String, u64)>)]) {
    let width = packages
        .iter()
        .flat_map(|(_, skills)| skills.iter().map(|(name, _)| name.len() + ".md".len()))
        .max()
        .unwrap_or(0);
    for (package, skills) in packages {
        println!("{}", format!("@lpm.dev/{package}").cyan());
        for (name, size) in skills {
            let file_name = format!("{name}.md");
            println!(
                "  {file_name:<width$}  {}",
                lpm_common::format_bytes(*size).dimmed()
            );
        }
        println!();
    }
}

fn validate_skills(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let skills_dir = project_dir.join(".lpm").join("skills");
    if !skills_dir.exists() {
        if !json_output {
            install_ui::warn("No .lpm/skills/ directory found");
        }
        return Ok(());
    }
    let mut errors = Vec::new();
    let mut valid = 0usize;
    let mut total_size = 0u64;
    for package in std::fs::read_dir(&skills_dir)?.flatten() {
        if !package.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        for skill in std::fs::read_dir(package.path())?.flatten() {
            let path = skill.path();
            if path.extension().is_none_or(|extension| extension != "md") {
                continue;
            }
            let display = format!(
                "{}/{}",
                package.file_name().to_string_lossy(),
                path.file_stem().unwrap_or_default().to_string_lossy()
            );
            let size = skill.metadata().map_or(0, |metadata| metadata.len());
            total_size += size;
            if size > 15 * 1024 {
                errors.push(format!("{display}: exceeds 15KB limit ({size} bytes)"));
                continue;
            }
            let content = std::fs::read_to_string(&path)?;
            if content.len() < 100 {
                errors.push(format!("{display}: content too short (need 100+ chars)"));
                continue;
            }
            let findings = lpm_security::skill_security::scan_skill_content(&content);
            if !findings.is_empty() {
                errors.push(format!(
                    "{display}: security scan found {} issue(s)",
                    findings.len()
                ));
                continue;
            }
            let (_, _, frontmatter_errors) =
                lpm_security::skill_security::parse_skill_frontmatter(&content);
            if frontmatter_errors.is_empty() {
                valid += 1;
            } else {
                errors.extend(
                    frontmatter_errors
                        .into_iter()
                        .map(|error| format!("{display}: {error}")),
                );
            }
        }
    }
    if total_size > 100 * 1024 {
        errors.push(format!(
            "total skills size {total_size} bytes exceeds 100KB limit"
        ));
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": errors.is_empty(),
                "valid": valid,
                "errors": errors,
                "quality_impact": if valid >= 3 { 10 } else if valid > 0 { 7 } else { 0 },
            }))
            .unwrap()
        );
    } else if errors.is_empty() {
        install_ui::done(&format!(
            "{valid} {} valid",
            plural(valid, "skill", "skills")
        ));
    } else {
        for error in &errors {
            install_ui::warn(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else if json_output {
        Err(LpmError::ExitCode(1))
    } else {
        Err(LpmError::Script(format!(
            "{} skill validation error(s)",
            errors.len()
        )))
    }
}

fn clean_skills(project_dir: &Path, json_output: bool) -> Result<(), LpmError> {
    let skills_dir = project_dir.join(".lpm").join("skills");
    if !skills_dir.exists() {
        if !json_output {
            install_ui::warn("No skills to clean");
        }
        return Ok(());
    }
    let removed = count_files_recursive(&skills_dir);
    std::fs::remove_dir_all(skills_dir)?;
    if json_output {
        println!(
            "{}",
            serde_json::json!({"success": true, "cleaned": true, "files_removed": removed})
        );
    } else {
        install_ui::done(&format!(
            "Skills cleaned · removed {removed} {}",
            plural(removed, "file", "files")
        ));
    }
    Ok(())
}

fn count_files_recursive(dir: &Path) -> usize {
    std::fs::read_dir(dir).map_or(0, |entries| {
        entries
            .flatten()
            .map(|entry| {
                if entry.path().is_dir() {
                    count_files_recursive(&entry.path())
                } else {
                    1
                }
            })
            .sum()
    })
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_skills_rejects_a_missing_requested_name() {
        let discovered = vec![source::DiscoveredSkill::for_test("release-notes")];
        let error = select_skills(&["missing".into()], &discovered, true).unwrap_err();
        assert!(error.to_string().contains("available: release-notes"));
    }

    #[test]
    fn package_inventory_ignores_non_markdown_files() {
        let project = tempfile::tempdir().unwrap();
        let package = project.path().join(".lpm/skills/example.package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join("guide.md"), "guide").unwrap();
        std::fs::write(package.join("note.txt"), "note").unwrap();

        let inventory = package_inventory(project.path()).unwrap();

        assert_eq!(
            inventory,
            vec![("example.package".into(), vec![("guide".into(), 5)])]
        );
    }
}
